package querylog

import "time"

// Result-Konstanten für QueryLogEntry.Result
const (
	ResultBlocked       = "blocked"
	ResultCached        = "cached"
	ResultAuthoritative = "authoritative"
	ResultForwarded     = "forwarded"
	ResultError         = "error"
)

// QueryLogEntry repräsentiert eine einzelne DNS-Anfrage im Query-Log.
type QueryLogEntry struct {
	Timestamp time.Time `json:"ts"`
	NodeID    string    `json:"node"`               // IP oder Hostname des DNS-Nodes
	ClientIP  string    `json:"client"`             // Anfragende Client-IP
	Domain    string    `json:"domain"`             // Angefragte Domain
	QType     string    `json:"qtype"`              // DNS-Record-Typ: "A", "AAAA", "MX", etc.
	Result    string    `json:"result"`             // "blocked", "cached", "authoritative", "forwarded", "error"
	Latency   int64     `json:"latency_us"`         // Antwortzeit in Mikrosekunden
	Upstream  string    `json:"upstream,omitempty"` // Upstream-Server der geantwortet hat (nur bei Result=forwarded)
	Blocked   bool      `json:"blocked"`
	Cached    bool      `json:"cached"`
	RCODE     int       `json:"rcode"` // DNS Response Code: 0=NOERROR, 3=NXDOMAIN, 2=SERVFAIL
}

// QueryLogFilter definiert Filterkriterien für GET /api/query-log.
type QueryLogFilter struct {
	Client string    // Prefix-Match auf ClientIP
	Domain string    // Substring-Match auf Domain
	Result string    // Exakt-Match auf Result
	QType  string    // Exakt-Match auf QType
	Node   string    // Exakt-Match auf NodeID
	Since  time.Time // Zeitraum-Start (Zero = kein Filter)
	Until  time.Time // Zeitraum-Ende (Zero = kein Filter)
	Limit  int       // Max Einträge (Default: 100, Max: 1000)
	Offset int       // Pagination-Offset
}

// QueryLogPage ist die paginierte Antwort für GET /api/query-log.
type QueryLogPage struct {
	Entries []QueryLogEntry `json:"entries"`
	Total   int             `json:"total"`
	HasMore bool            `json:"has_more"`
}

// QueryLogStats enthält aggregierte Statistiken.
type QueryLogStats struct {
	TotalQueries   int64        `json:"total_queries"`
	BlockRate      float64      `json:"block_rate"` // 0.0–1.0
	TopClients     []ClientStat `json:"top_clients"`
	TopDomains     []DomainStat `json:"top_domains"`
	TopBlocked     []DomainStat `json:"top_blocked"`
	QueriesPerHour []HourStat   `json:"queries_per_hour"` // Letzte 24h
}

// ClientStat enthält Statistiken für einen einzelnen Client.
type ClientStat struct {
	ClientIP string `json:"client"`
	Count    int64  `json:"count"`
}

// DomainStat enthält Statistiken für eine einzelne Domain.
type DomainStat struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

// HourStat enthält Query-Volumen für eine Stunde.
type HourStat struct {
	Hour  time.Time `json:"hour"`
	Count int64     `json:"count"`
}

// SyncPayload ist das Format für den Batch-Push Slave → Master.
type SyncPayload struct {
	HMAC    string          `json:"hmac"`
	NodeID  string          `json:"node"`
	Entries []QueryLogEntry `json:"entries"`
}
