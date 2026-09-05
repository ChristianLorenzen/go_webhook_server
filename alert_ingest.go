package main

// Generic in-house alert ingress — POST /ingest/alert/v1
//
// A single versioned endpoint any internal service can post to with one shared
// secret, so RabbitMQ credentials never have to be distributed to scripts/hosts.
//
// Contract (all unknown fields are IGNORED, never rejected — forward compatible):
//
//	POST /ingest/alert/v1
//	X-Ingest-Token: <ALERT_INGEST_TOKEN>
//	{
//	  "source": "proxmox-auto-update",           // required, stable slug
//	  "event": "update-run.container",           // required, machine-parseable type
//	  "severity": "warning",                     // required: info|success|warning|error|critical
//	  "title": "nginx-proxy-manager (105) — PARTIAL",  // required
//	  "message": "full human-readable text",     // required — a complete alert on its own
//	  "timestamp": "2026-09-05T09:00:00Z",       // optional; defaults to now if absent/unparseable
//	  "tags": ["proxmox","homelab"],             // optional
//	  "fields": [{"name":"vmid","value":"105"}], // optional structured key/values
//	  "link": null,                              // optional http(s) URL
//	  "dedupe_key": "..."                        // optional, for future collapse/resolve
//	}
//
// Published routing key: alert.<source>.<severity>.<event>  (matches the homelab
// alert.<source>.<severity>.<type> convention, so `alert.#` consumers pick it up and
// you can later bind e.g. `alert.*.critical.#` to a louder queue).
//
// ── Threat model / hardening ─────────────────────────────────────────────────
// This service is publicly routable, so every field is treated as hostile input.
// Go's JSON decoding has no code-execution path (no eval, no deserialization
// gadgets), so the realistic risks are abuse rather than RCE, and are handled here:
//
//   - Unauthenticated abuse .. shared-secret header compared in constant time,
//     PLUS the caller must be inside LAN_SUBNET (this endpoint is for in-house use).
//   - Flooding / alert spam ... per-endpoint rate limit + 512 KB body cap.
//   - Routing-key injection .. source/event are reduced to [a-z0-9-] segments, so a
//     caller cannot inject '.', '*' or '#' to reach unintended queue bindings.
//   - Discord mass-ping ...... @everyone/@here and <@user|role> mention syntax are
//     defused before the text ever reaches Apprise → Discord.
//   - Log injection .......... control characters (incl. CR/LF) stripped from all
//     text; only sanitised values are logged.
//   - Memory blowup .......... tag/field counts and every string length are capped.
//   - Broken encoding ........ invalid UTF-8 is dropped so downstream JSON/consumers
//     never receive malformed strings.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// ── Limits ────────────────────────────────────────────────────────────────────

const (
	alertMaxTags          = 16
	alertMaxFields        = 24
	alertMaxSourceLen     = 64
	alertMaxEventLen      = 64
	alertMaxTitleLen      = 256
	alertMaxMessageLen    = 4000
	alertMaxTagLen        = 32
	alertMaxFieldNameLen  = 64
	alertMaxFieldValueLen = 512
	alertMaxLinkLen       = 2048
	alertMaxDedupeKeyLen  = 128
	alertMaxBodyLen       = 6000 // message + rendered fields + link
)

// ── Payload ───────────────────────────────────────────────────────────────────

type alertFieldIn struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// alertPayloadV1 mirrors the documented contract. Unknown JSON members are
// deliberately ignored (we do NOT use DisallowUnknownFields) so producers can add
// fields ahead of a server change.
type alertPayloadV1 struct {
	Source    string         `json:"source"`
	Event     string         `json:"event"`
	Severity  string         `json:"severity"`
	Title     string         `json:"title"`
	Message   string         `json:"message"`
	Timestamp string         `json:"timestamp"`
	Tags      []string       `json:"tags"`
	Fields    []alertFieldIn `json:"fields"`
	Link      string         `json:"link"`
	DedupeKey string         `json:"dedupe_key"`
}

// Incoming severity vocabulary → the homelab envelope vocabulary
// (low | medium | high | critical) that existing consumers already understand.
var alertSeverityMap = map[string]string{
	"info":     "low",
	"success":  "low",
	"warning":  "medium",
	"error":    "high",
	"critical": "critical",
}

// ── Handler ───────────────────────────────────────────────────────────────────

// handleAlertV1 accepts the generic in-house alert envelope.
//
// Security layers, fail-fast in order:
//  1. Endpoint disabled entirely unless ALERT_INGEST_TOKEN is configured
//  2. POST only
//  3. Rate limit (protects Apprise/Discord from a flood)
//  4. Source IP must be inside LAN_SUBNET — in-house services only
//  5. X-Ingest-Token must match, compared in constant time
//  6. Body size cap, then strict validation + sanitisation of every field
func (s *server) handleAlertV1(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AlertIngestToken == "" {
		http.NotFound(w, r) // not configured → endpoint does not exist
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.alertLimiter.Allow() {
		s.logger.Warn("alert ingest rate limit exceeded", "remote", r.RemoteAddr)
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	ip := realIP(r)
	if ip == nil || !s.lanNet.Contains(ip) {
		s.logger.Warn("alert ingest from outside LAN — rejected", "ip", ipStr(ip))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !secureEqual(r.Header.Get("X-Ingest-Token"), s.cfg.AlertIngestToken) {
		s.logger.Warn("alert ingest token mismatch", "ip", ipStr(ip))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	body, err := readBody(r)
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	var payload alertPayloadV1
	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	env, err := normalizeAlertV1(payload)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := s.mq.publish(env.RoutingKey, env); err != nil {
		s.logger.Error("failed to publish in-house alert", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Only sanitised values are logged (control characters already stripped).
	s.logger.Info("in-house alert published",
		"routing_key", env.RoutingKey,
		"source", env.Source,
		"severity", env.Severity,
		"ip", ipStr(ip),
	)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "accepted",
		"id":          env.ID,
		"routing_key": env.RoutingKey,
	})
}

// ── Normalisation + validation ────────────────────────────────────────────────

func normalizeAlertV1(p alertPayloadV1) (Envelope, error) {
	source := sanitizeText(p.Source, alertMaxSourceLen)
	event := sanitizeText(p.Event, alertMaxEventLen)
	title := sanitizeText(p.Title, alertMaxTitleLen)
	message := sanitizeText(p.Message, alertMaxMessageLen)
	rawSeverity := strings.ToLower(strings.TrimSpace(sanitizeText(p.Severity, 16)))

	var missing []string
	if source == "" {
		missing = append(missing, "source")
	}
	if event == "" {
		missing = append(missing, "event")
	}
	if title == "" {
		missing = append(missing, "title")
	}
	if message == "" {
		missing = append(missing, "message")
	}
	if len(missing) > 0 {
		return Envelope{}, fmt.Errorf("missing required field(s): %s", strings.Join(missing, ", "))
	}

	severity, ok := alertSeverityMap[rawSeverity]
	if !ok {
		return Envelope{}, fmt.Errorf(
			"invalid severity %q: must be one of info, success, warning, error, critical", rawSeverity)
	}

	// Routing-key segments are reduced to [a-z0-9-] so '.', '*' and '#' can never be
	// injected to reach bindings the caller shouldn't reach.
	sourceKey := sanitizeKeySegment(source, alertMaxSourceLen, "unknown")
	eventKey := sanitizeKeySegment(event, alertMaxEventLen, "event")
	routingKey := fmt.Sprintf("alert.%s.%s.%s", sourceKey, severity, eventKey)

	tags := sanitizeStringSlice(p.Tags, alertMaxTags, alertMaxTagLen)

	fields := make([]map[string]string, 0, len(p.Fields))
	for _, f := range p.Fields {
		if len(fields) >= alertMaxFields {
			break
		}
		name := sanitizeText(f.Name, alertMaxFieldNameLen)
		value := sanitizeText(f.Value, alertMaxFieldValueLen)
		if name == "" && value == "" {
			continue
		}
		fields = append(fields, map[string]string{"name": name, "value": value})
	}

	link := safeLink(p.Link)
	dedupeKey := sanitizeText(p.DedupeKey, alertMaxDedupeKeyLen)

	metadata := map[string]any{
		"schema":      "alert.v1",
		"event":       event,
		"severity_in": rawSeverity,
	}
	if len(tags) > 0 {
		metadata["tags"] = tags
	}
	if len(fields) > 0 {
		metadata["fields"] = fields
	}
	if link != "" {
		metadata["link"] = link
	}
	if dedupeKey != "" {
		metadata["dedupe_key"] = dedupeKey
	}

	return Envelope{
		ID:         uuid.New().String(),
		Timestamp:  normalizeTimestamp(p.Timestamp),
		Source:     source,
		RoutingKey: routingKey,
		Severity:   severity,
		AlertEvent: "",
		Title:      neutralizeMentions(title),
		Body:       neutralizeMentions(buildAlertBody(message, fields, link)),
		Metadata:   metadata,
	}, nil
}

// buildAlertBody renders the human-readable body: the message is always a complete
// alert on its own; fields and link are appended so they're visible in Discord,
// which only receives title + body text.
func buildAlertBody(message string, fields []map[string]string, link string) string {
	var b strings.Builder
	b.WriteString(message)
	for _, f := range fields {
		b.WriteString("\n")
		switch {
		case f["name"] == "":
			b.WriteString(f["value"])
		case f["value"] == "":
			b.WriteString(f["name"])
		default:
			b.WriteString(f["name"] + ": " + f["value"])
		}
	}
	if link != "" {
		b.WriteString("\n" + link)
	}
	return truncateRunes(b.String(), alertMaxBodyLen)
}

// ── Sanitisation helpers ──────────────────────────────────────────────────────

// sanitizeText makes an arbitrary caller-supplied string safe to store, log and
// forward: valid UTF-8 only, no control characters (so no CR/LF log injection or
// terminal escapes), trimmed, and length-capped.
func sanitizeText(s string, maxRunes int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r // keep intentional formatting
		case r == '\r':
			return -1 // normalise CRLF → LF
		case unicode.IsControl(r):
			return -1
		default:
			return r
		}
	}, s)
	return truncateRunes(strings.TrimSpace(s), maxRunes)
}

// sanitizeKeySegment reduces a string to a single safe AMQP routing-key segment:
// lowercase [a-z0-9-] only. '.', '*' and '#' collapse to '-', so a caller cannot
// break out of their segment and match other bindings.
func sanitizeKeySegment(s string, maxRunes int, fallback string) string {
	s = strings.ToLower(strings.ToValidUTF8(s, ""))

	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteRune('-')
				lastDash = true
			}
		}
	}

	out := strings.Trim(b.String(), "-")
	if r := []rune(out); len(r) > maxRunes {
		out = strings.Trim(string(r[:maxRunes]), "-")
	}
	if out == "" {
		return fallback
	}
	return out
}

func sanitizeStringSlice(in []string, maxItems, maxLen int) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if len(out) >= maxItems {
			break
		}
		if v = sanitizeText(v, maxLen); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// neutralizeMentions defuses Discord mass-pings and user/role mentions by inserting
// a zero-width space. Text stays readable; a compromised producer can't @everyone.
var alertMentionRe = regexp.MustCompile(`(?i)@(everyone|here)`)

func neutralizeMentions(s string) string {
	const zwsp = "​" // zero-width space: breaks the mention, invisible to readers
	s = alertMentionRe.ReplaceAllString(s, "@"+zwsp+"$1")
	return strings.ReplaceAll(s, "<@", "<"+zwsp+"@")
}

// safeLink accepts only absolute http(s) URLs — blocks javascript:, data:, file:
// and similar schemes in case the value is ever rendered in a UI.
func safeLink(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > alertMaxLinkLen {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return u.String()
}

// normalizeTimestamp accepts RFC3339/ISO-8601 UTC and falls back to now, so a bad
// clock or a lazy producer can never drop an alert.
func normalizeTimestamp(s string) string {
	if s = strings.TrimSpace(s); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return time.Now().UTC().Format(time.RFC3339)
}

func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes-1]) + "…"
}
