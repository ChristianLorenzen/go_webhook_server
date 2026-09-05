package main

// Webhook Receiver — homelab alerting ingress
//
// Accepts webhook POSTs from Cloudflare Notifications and Grafana Alerting,
// normalises each payload into a standard envelope, and publishes it to
// RabbitMQ on the homelab.alerts topic exchange.
//
// Security model:
//   /ingest/cloudflare — source IP must be in Cloudflare's published ranges
//                        AND cf-webhook-auth header must match configured secret
//   /ingest/grafana    — source IP must be within the configured LAN subnet
//                        AND X-Webhook-Token header must match configured token
//   /ingest/alert/v1   — generic in-house ingress (see alert_ingest.go): LAN subnet
//                        AND X-Ingest-Token, with full field sanitisation
//
// Configuration (environment variables):
//   LISTEN_ADDR            HTTP listen address (default :8080)
//   RABBITMQ_URL           AMQP URL (default amqp://guest:guest@192.168.15.50:5672/)
//   CF_WEBHOOK_SECRET      Secret set in Cloudflare Notifications → Destinations → Webhooks
//   GRAFANA_WEBHOOK_TOKEN  Shared token set in Grafana contact point header
//   UPTIME_KUMA_TOKEN      Shared token for Uptime Kuma (endpoint disabled if unset)
//   ALERT_INGEST_TOKEN     Shared secret for /ingest/alert/v1 (endpoint disabled if unset)
//   LAN_SUBNET             CIDR for internal clients (default 192.168.15.0/24)

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"golang.org/x/time/rate"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	maxBodyBytes     = 512 * 1024 // 512 KB — generous for any webhook payload
	cfIPsAPIURL      = "https://api.cloudflare.com/client/v4/ips"
	cfIPRefreshEvery = 12 * time.Hour // CF IPs change rarely; 12h is safe
	amqpRetryBase    = 2 * time.Second
	amqpRetryMax     = 60 * time.Second
	alertsExchange   = "homelab.alerts"
)

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	ListenAddr       string
	RabbitMQURL      string
	CFSecret         string
	GrafanaToken     string
	UptimeKumaToken  string
	AlertIngestToken string
	LANSubnet        string
}

func loadConfig() (Config, error) {
	get := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return def
	}
	cfg := Config{
		ListenAddr:       get("LISTEN_ADDR", ":8080"),
		RabbitMQURL:      get("RABBITMQ_URL", "amqp://guest:guest@192.168.15.50:5672/"),
		CFSecret:         get("CF_WEBHOOK_SECRET", ""),
		GrafanaToken:     get("GRAFANA_WEBHOOK_TOKEN", ""),
		UptimeKumaToken:  get("UPTIME_KUMA_TOKEN", ""),
		AlertIngestToken: get("ALERT_INGEST_TOKEN", ""),
		LANSubnet:        get("LAN_SUBNET", "192.168.15.0/24"),
	}
	if cfg.CFSecret == "" {
		return cfg, fmt.Errorf("CF_WEBHOOK_SECRET must be set")
	}
	if cfg.GrafanaToken == "" {
		return cfg, fmt.Errorf("GRAFANA_WEBHOOK_TOKEN must be set")
	}
	return cfg, nil
}

// ── Message Envelope ──────────────────────────────────────────────────────────

// Envelope is the standard message shape published to every RabbitMQ exchange.
// Custom project publishers should conform to this same structure.
type Envelope struct {
	ID         string         `json:"id"`
	Timestamp  string         `json:"timestamp"`
	Source     string         `json:"source"`
	RoutingKey string         `json:"routing_key"`
	Severity   string         `json:"severity"`    // low | medium | high | critical
	AlertEvent string         `json:"alert_event"` // start | end | (empty for non-alerts)
	Title      string         `json:"title"`
	Body       string         `json:"body"`
	Metadata   map[string]any `json:"metadata"`
}

// ── AMQP Manager ─────────────────────────────────────────────────────────────

// amqpManager holds a single AMQP connection and channel, reconnecting
// automatically with exponential backoff when either is lost.
type amqpManager struct {
	url    string
	mu     sync.Mutex
	conn   *amqp.Connection
	ch     *amqp.Channel
	logger *slog.Logger
}

func newAMQPManager(url string, logger *slog.Logger) (*amqpManager, error) {
	m := &amqpManager{url: url, logger: logger}
	if err := m.dial(); err != nil {
		return nil, fmt.Errorf("initial rabbitmq connection failed: %w", err)
	}
	return m, nil
}

func (m *amqpManager) dial() error {
	conn, err := amqp.Dial(m.url)
	if err != nil {
		return err
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return err
	}
	// Declare the alerts exchange as durable so it survives a broker restart.
	// type=topic lets consumers bind with routing key patterns like alert.#
	if err := ch.ExchangeDeclare(
		alertsExchange, "topic",
		true,  // durable
		false, // auto-delete
		false, // internal
		false, // no-wait
		nil,
	); err != nil {
		conn.Close()
		return fmt.Errorf("declare exchange: %w", err)
	}
	m.mu.Lock()
	m.conn = conn
	m.ch = ch
	m.mu.Unlock()
	m.logger.Info("rabbitmq connected", "url", redactURL(m.url))
	return nil
}

// reconnect blocks until a connection is re-established with exponential backoff.
func (m *amqpManager) reconnect() {
	backoff := amqpRetryBase
	for {
		m.logger.Warn("rabbitmq reconnecting", "in", backoff)
		time.Sleep(backoff)
		if err := m.dial(); err == nil {
			return
		}
		if backoff < amqpRetryMax {
			backoff *= 2
		}
	}
}

// publish serialises env and publishes it. On channel error it reconnects once
// and retries. Messages are marked persistent so they survive a broker restart.
func (m *amqpManager) publish(routingKey string, env Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	m.mu.Lock()
	ch := m.ch
	m.mu.Unlock()

	pub := amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		Timestamp:    time.Now().UTC(),
		Body:         body,
	}

	if err := ch.Publish(alertsExchange, routingKey, false, false, pub); err != nil {
		// Channel is likely broken — reconnect and retry once.
		m.logger.Warn("publish failed, reconnecting", "err", err)
		m.reconnect()
		m.mu.Lock()
		ch = m.ch
		m.mu.Unlock()
		return ch.Publish(alertsExchange, routingKey, false, false, pub)
	}
	return nil
}

func redactURL(raw string) string {
	u, err := amqp.ParseURI(raw)
	if err != nil {
		return "amqp://[redacted]"
	}
	return fmt.Sprintf("amqp://%s:***@%s:%d/%s", u.Username, u.Host, u.Port, u.Vhost)
}

// ── Cloudflare IP Allowlist ───────────────────────────────────────────────────

type cfIPList struct {
	mu     sync.RWMutex
	ranges []*net.IPNet
	logger *slog.Logger
}

type cfIPAPIResponse struct {
	Result struct {
		IPv4CIDRs []string `json:"ipv4_cidrs"`
		IPv6CIDRs []string `json:"ipv6_cidrs"`
	} `json:"result"`
	Success bool `json:"success"`
}

// newCFIPList fetches Cloudflare IP ranges from the Cloudflare API at startup
// and refreshes them on a schedule. If a refresh returns an empty list, the
// previous list is kept so a transient API failure doesn't open the gate.
func newCFIPList(logger *slog.Logger) *cfIPList {
	l := &cfIPList{logger: logger}
	l.refresh()
	go func() {
		t := time.NewTicker(cfIPRefreshEvery)
		for range t.C {
			l.refresh()
		}
	}()
	return l
}

func (l *cfIPList) refresh() {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(cfIPsAPIURL)
	if err != nil {
		l.logger.Warn("cloudflare IP refresh failed", "err", err)
		return
	}
	defer resp.Body.Close()

	var apiResp cfIPAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil || !apiResp.Success {
		l.logger.Warn("cloudflare IP refresh: unexpected response")
		return
	}

	var nets []*net.IPNet
	for _, cidr := range append(apiResp.Result.IPv4CIDRs, apiResp.Result.IPv6CIDRs...) {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipnet)
		}
	}
	if len(nets) == 0 {
		l.logger.Warn("cloudflare IP refresh: empty list, keeping previous list")
		return
	}
	l.mu.Lock()
	l.ranges = nets
	l.mu.Unlock()
	l.logger.Info("cloudflare IP list refreshed", "count", len(nets))
}

func (l *cfIPList) contains(ip net.IP) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, n := range l.ranges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ── Server ────────────────────────────────────────────────────────────────────

type server struct {
	cfg    Config
	mq     *amqpManager
	cfIPs  *cfIPList
	lanNet *net.IPNet
	logger *slog.Logger
	// Rate limiter for the public Cloudflare endpoint.
	// 10 req/s sustained, burst of 20. Actual CF notification volume is very
	// low; this only triggers on abuse or scanning from CF IP space.
	cfLimiter *rate.Limiter
	// Rate limiter for /ingest/alert/v1. In-house alert volume is low; this caps how
	// fast any internal (or compromised) service can drive notifications to Discord.
	// 5 req/s sustained, burst of 20.
	alertLimiter *rate.Limiter
}

func newServer(cfg Config, logger *slog.Logger) (*server, error) {
	_, lanNet, err := net.ParseCIDR(cfg.LANSubnet)
	if err != nil {
		return nil, fmt.Errorf("invalid LAN_SUBNET %q: %w", cfg.LANSubnet, err)
	}
	mq, err := newAMQPManager(cfg.RabbitMQURL, logger)
	if err != nil {
		return nil, err
	}
	return &server{
		cfg:          cfg,
		mq:           mq,
		cfIPs:        newCFIPList(logger),
		lanNet:       lanNet,
		logger:       logger,
		cfLimiter:    rate.NewLimiter(rate.Every(100*time.Millisecond), 20),
		alertLimiter: rate.NewLimiter(rate.Every(200*time.Millisecond), 20),
	}, nil
}

// realIP returns the originating client IP, preferring the X-Real-IP header
// set by Nginx Proxy Manager. X-Forwarded-For is intentionally NOT used here
// because it can be prepended by clients before NPM appends the real upstream;
// X-Real-IP is set exclusively by NPM to the direct connecting client.
func realIP(r *http.Request) net.IP {
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// handleCloudflare accepts Cloudflare Notification webhooks.
//
// Security layers (applied in order — fail fast):
//  1. POST method enforcement
//  2. Rate limiting (prevents flood/scanning even from CF IP space)
//  3. Source IP must be in Cloudflare's published egress ranges
//  4. cf-webhook-auth header must equal the configured secret (constant-time)
func (s *server) handleCloudflare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.cfLimiter.Allow() {
		s.logger.Warn("cloudflare endpoint rate limit exceeded", "remote", r.RemoteAddr)
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	ip := realIP(r)
	if ip == nil || !s.cfIPs.contains(ip) {
		s.logger.Warn("cloudflare request from non-CF IP — rejected",
			"ip", ipStr(ip), "path", r.URL.Path)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Cloudflare sends the raw secret in cf-webhook-auth.
	// Use constant-time comparison to prevent timing oracle attacks.
	if !secureEqual(r.Header.Get("Cf-Webhook-Auth"), s.cfg.CFSecret) {
		s.logger.Warn("cloudflare webhook secret mismatch", "ip", ipStr(ip))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	body, err := readBody(r)
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	var payload cfPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	env := normalizeCF(payload)
	if err := s.mq.publish(env.RoutingKey, env); err != nil {
		s.logger.Error("failed to publish cloudflare alert", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.logger.Info("cloudflare alert published",
		"routing_key", env.RoutingKey,
		"alert_type", payload.AlertType,
		"alert_event", payload.AlertEvent,
	)
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

// handleGrafana accepts Grafana Unified Alerting webhook contact point calls.
//
// Security layers:
//  1. POST method enforcement
//  2. Source IP must be within the LAN subnet (Grafana is internal — never public)
//  3. X-Webhook-Token header must equal the configured token (constant-time)
func (s *server) handleGrafana(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := realIP(r)
	if ip == nil || !s.lanNet.Contains(ip) {
		s.logger.Warn("grafana request from outside LAN — rejected", "ip", ipStr(ip))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if !secureEqual(r.Header.Get("X-Webhook-Token"), s.cfg.GrafanaToken) {
		s.logger.Warn("grafana webhook token mismatch", "ip", ipStr(ip))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	body, err := readBody(r)
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	var payload grafanaPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	env := normalizeGrafana(payload)
	if err := s.mq.publish(env.RoutingKey, env); err != nil {
		s.logger.Error("failed to publish grafana alert", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.logger.Info("grafana alert published",
		"routing_key", env.RoutingKey,
		"state", payload.State,
	)
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

// handleUptimeKuma accepts Uptime Kuma webhook notifications.
//
// Security layers:
//  1. POST method enforcement
//  2. Source IP must be within the LAN subnet (Uptime Kuma is internal)
//  3. X-Webhook-Token header must equal the configured token (constant-time)
//
// If UPTIME_KUMA_TOKEN is not set the endpoint is disabled and returns 404,
// so it's safe to deploy without Uptime Kuma configured.
func (s *server) handleUptimeKuma(w http.ResponseWriter, r *http.Request) {
	if s.cfg.UptimeKumaToken == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := realIP(r)
	if ip == nil || !s.lanNet.Contains(ip) {
		s.logger.Warn("uptime kuma request from outside LAN — rejected", "ip", ipStr(ip))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if !secureEqual(r.Header.Get("X-Webhook-Token"), s.cfg.UptimeKumaToken) {
		s.logger.Warn("uptime kuma webhook token mismatch", "ip", ipStr(ip))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	body, err := readBody(r)
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	var payload uptimeKumaPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	env := normalizeUptimeKuma(payload)
	if err := s.mq.publish(env.RoutingKey, env); err != nil {
		s.logger.Error("failed to publish uptime kuma alert", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.logger.Info("uptime kuma alert published",
		"routing_key", env.RoutingKey,
		"monitor", payload.Monitor.Name,
		"status", payload.Heartbeat.Status,
	)
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

// handleHealth is a simple liveness probe — useful for the Homepage dashboard
// widget and for uptime monitoring via Prometheus/Grafana itself.
func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Payload types ─────────────────────────────────────────────────────────────

// cfPayload mirrors the Cloudflare generic webhook schema.
// Reference: https://developers.cloudflare.com/notifications/reference/webhook-payload-schema/
type cfPayload struct {
	Name               string         `json:"name"`
	Text               string         `json:"text"`
	Data               map[string]any `json:"data"`
	Ts                 int64          `json:"ts"`
	AccountID          string         `json:"account_id"`
	PolicyID           string         `json:"policy_id"`
	PolicyName         string         `json:"policy_name"`
	AlertType          string         `json:"alert_type"`
	AlertCorrelationID string         `json:"alert_correlation_id"`
	AlertEvent         string         `json:"alert_event"`
}

// grafanaPayload mirrors the Grafana Unified Alerting webhook schema.
// Reference: https://grafana.com/docs/grafana/latest/alerting/alerting-rules/manage-contact-points/webhook-notifier/
type grafanaPayload struct {
	Title             string         `json:"title"`
	State             string         `json:"state"` // alerting | ok | pending | no_data
	Message           string         `json:"message"`
	OrgID             int            `json:"orgId"`
	CommonLabels      map[string]any `json:"commonLabels"`
	CommonAnnotations map[string]any `json:"commonAnnotations"`
	Alerts            []grafanaAlert `json:"alerts"`
}

type grafanaAlert struct {
	Status      string         `json:"status"`
	Labels      map[string]any `json:"labels"`
	Annotations map[string]any `json:"annotations"`
	StartsAt    string         `json:"startsAt"`
	EndsAt      string         `json:"endsAt"`
	Fingerprint string         `json:"fingerprint"`
}

// uptimeKumaPayload mirrors the Uptime Kuma webhook notification schema.
// Reference: https://github.com/louislam/uptime-kuma/wiki/Notification-Methods/webhook
type uptimeKumaPayload struct {
	Heartbeat struct {
		Status   int    `json:"status"` // 1 = up, 0 = down
		Time     string `json:"time"`
		Msg      string `json:"msg"`
		Ping     int    `json:"ping"`
		Duration int    `json:"duration"`
	} `json:"heartbeat"`
	Monitor struct {
		Name string `json:"name"`
		URL  string `json:"url"`
		Type string `json:"type"`
	} `json:"monitor"`
	Msg string `json:"msg"`
}

// ── Normalisation ─────────────────────────────────────────────────────────────

func normalizeCF(p cfPayload) Envelope {
	severity := cfAlertSeverity(p.AlertType)

	alertType := p.AlertType
	if alertType == "" {
		alertType = "unknown"
	}
	// Routing key format: alert.cloudflare.<severity>.<alert_type>
	// Example: alert.cloudflare.high.advanced_ddos_attack_l4_alert
	routingKey := fmt.Sprintf("alert.cloudflare.%s.%s", severity, alertType)

	alertEvent := ""
	switch p.AlertEvent {
	case "ALERT_STATE_EVENT_START":
		alertEvent = "start"
	case "ALERT_STATE_EVENT_END":
		alertEvent = "end"
	}

	title := p.Text
	if title == "" {
		title = fmt.Sprintf("Cloudflare: %s", alertType)
	}

	bodyBytes, _ := json.Marshal(p.Data)

	return Envelope{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Source:     "cloudflare",
		RoutingKey: routingKey,
		Severity:   severity,
		AlertEvent: alertEvent,
		Title:      title,
		Body:       string(bodyBytes),
		Metadata: map[string]any{
			"account_id":           p.AccountID,
			"policy_id":            p.PolicyID,
			"policy_name":          p.PolicyName,
			"alert_type":           p.AlertType,
			"alert_correlation_id": p.AlertCorrelationID,
			"alert_event_raw":      p.AlertEvent,
			"ts":                   p.Ts,
		},
	}
}

// cfAlertSeverity maps Cloudflare alert_type strings to severity levels.
// Extend this as you subscribe to more notification types in the CF dashboard.
func cfAlertSeverity(alertType string) string {
	t := strings.ToLower(alertType)
	switch {
	case strings.Contains(t, "ddos") ||
		strings.Contains(t, "under_attack") ||
		strings.Contains(t, "origin_error") ||
		strings.Contains(t, "failover"):
		return "high"
	case strings.Contains(t, "health") ||
		strings.Contains(t, "ssl") ||
		strings.Contains(t, "certificate") ||
		strings.Contains(t, "expir"):
		return "medium"
	default:
		return "low"
	}
}

func normalizeGrafana(p grafanaPayload) Envelope {
	severity := grafanaSeverity(p.State)

	// Use alertname label for a readable routing key component.
	alertName := "metric"
	if name, ok := p.CommonLabels["alertname"].(string); ok && name != "" {
		alertName = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), " ", "_"))
	}
	// Routing key format: alert.local.<severity>.<alertname>
	// Example: alert.local.high.disk_space_critical
	routingKey := fmt.Sprintf("alert.local.%s.%s", severity, alertName)

	title := p.Title
	if title == "" {
		title = fmt.Sprintf("Grafana alert: %s", alertName)
	}
	body := p.Message
	if body == "" {
		body = fmt.Sprintf("State: %s | %d alert(s) firing", p.State, len(p.Alerts))
	}

	return Envelope{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Source:     "grafana",
		RoutingKey: routingKey,
		Severity:   severity,
		AlertEvent: grafanaEvent(p.State),
		Title:      title,
		Body:       body,
		Metadata: map[string]any{
			"state":              p.State,
			"common_labels":      p.CommonLabels,
			"common_annotations": p.CommonAnnotations,
			"alert_count":        len(p.Alerts),
		},
	}
}

func grafanaSeverity(state string) string {
	switch strings.ToLower(state) {
	case "alerting", "firing":
		return "high"
	case "pending":
		return "medium"
	default: // ok, no_data, paused
		return "low"
	}
}

func grafanaEvent(state string) string {
	switch strings.ToLower(state) {
	case "alerting", "firing", "pending":
		return "start"
	case "ok":
		return "end"
	default:
		return ""
	}
}

func normalizeUptimeKuma(p uptimeKumaPayload) Envelope {
	severity := "high"
	alertEvent := "start"
	if p.Heartbeat.Status == 1 {
		severity = "low"
		alertEvent = "end"
	}

	monitorName := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p.Monitor.Name), " ", "_"))
	if monitorName == "" {
		monitorName = "unknown"
	}
	// Routing key: alert.local.<severity>.uptime_kuma_<monitor_name>
	// Example: alert.local.high.uptime_kuma_gitea
	routingKey := fmt.Sprintf("alert.local.%s.uptime_kuma_%s", severity, monitorName)

	title := p.Msg
	if title == "" {
		status := "down"
		if p.Heartbeat.Status == 1 {
			status = "up"
		}
		title = fmt.Sprintf("%s is %s", p.Monitor.Name, status)
	}

	return Envelope{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Source:     "uptime-kuma",
		RoutingKey: routingKey,
		Severity:   severity,
		AlertEvent: alertEvent,
		Title:      title,
		Body:       p.Heartbeat.Msg,
		Metadata: map[string]any{
			"monitor_name": p.Monitor.Name,
			"monitor_url":  p.Monitor.URL,
			"monitor_type": p.Monitor.Type,
			"status":       p.Heartbeat.Status,
			"ping_ms":      p.Heartbeat.Ping,
		},
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// secureEqual compares two strings in constant time to prevent timing attacks.
// An empty string on either side is always rejected — callers must provide
// actual values; a missing header should never succeed.
func secureEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func readBody(r *http.Request) ([]byte, error) {
	// LimitReader caps how much we'll read; the +1 lets us detect an
	// oversized body by checking if we got more than maxBodyBytes bytes.
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBodyBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", maxBodyBytes)
	}
	return data, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func ipStr(ip net.IP) string {
	if ip == nil {
		return "<nil>"
	}
	return ip.String()
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("configuration error", "err", err)
		os.Exit(1)
	}

	srv, err := newServer(cfg, logger)
	if err != nil {
		logger.Error("failed to initialise server", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ingest/cloudflare", srv.handleCloudflare)
	mux.HandleFunc("/ingest/grafana", srv.handleGrafana)
	mux.HandleFunc("/ingest/uptime-kuma", srv.handleUptimeKuma)
	mux.HandleFunc("/ingest/alert/v1", srv.handleAlertV1)
	mux.HandleFunc("/health", srv.handleHealth)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second, // mitigates Slowloris
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 14, // 16 KB
	}

	go func() {
		logger.Info("webhook receiver listening", "addr", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server error", "err", err)
			os.Exit(1)
		}
	}()

	// Block until SIGINT or SIGTERM, then drain in-flight requests gracefully.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	logger.Info("shutting down", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Error("shutdown error", "err", err)
	}
	logger.Info("shutdown complete")
}
