package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration for YAML parsing (e.g., "5s", "2m").
type Duration time.Duration

func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// MarshalJSON implements json.Marshaler for human-readable duration (e.g. "24h").
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON implements json.Unmarshaler for duration strings (e.g. "24h").
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// DHCPLeaseSyncConfig configures automatic DNS record creation from DHCP leases.
type DHCPLeaseSyncConfig struct {
	// Enabled activates DHCP lease sync.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Source is the DHCP server type: "dnsmasq", "dhcpd", "fritzbox".
	Source string `yaml:"source" json:"source"`
	// SourcePath is the path to the lease file (dnsmasq/dhcpd).
	SourcePath string `yaml:"source_path" json:"source_path"`
	// Zone is the forward zone for A records (e.g. "home.lan").
	Zone string `yaml:"zone" json:"zone"`
	// ReverseZone is the reverse zone for PTR records (empty = auto-derived from IP).
	ReverseZone string `yaml:"reverse_zone" json:"reverse_zone"`
	// TTL for DHCP-generated records. Default: 60.
	TTL int `yaml:"ttl" json:"ttl"`
	// PollInterval is the polling interval for lease files. Default: 30s.
	PollInterval Duration `yaml:"poll_interval" json:"poll_interval"`
	// AutoCreateZone automatically creates forward/reverse zones if not present.
	AutoCreateZone bool `yaml:"auto_create_zone" json:"auto_create_zone"`
	// FritzBoxURL is the TR-064 URL of the FritzBox (e.g. "http://192.168.178.1:49000").
	FritzBoxURL string `yaml:"fritzbox_url" json:"fritzbox_url"`
	// FritzBoxUser is the username for FritzBox authentication.
	FritzBoxUser string `yaml:"fritzbox_user" json:"fritzbox_user"`
	// FritzBoxPassword is loaded from DOMUDNS_FRITZBOX_PASSWORD (never stored in YAML).
	FritzBoxPassword string `yaml:"-" json:"-"`
}

// Config is the root configuration structure.
type Config struct {
	DNSServer     DNSServerConfig     `yaml:"dnsserver" json:"dnsserver"`
	Caddy         CaddyConfig         `yaml:"caddy" json:"caddy"`
	Cluster       ClusterConfig       `yaml:"cluster" json:"cluster"`
	Acme          AcmeConfig          `yaml:"acme" json:"acme"`
	System        SystemConfig        `yaml:"system" json:"system"`
	Blocklist     BlocklistConfig     `yaml:"blocklist" json:"blocklist"`
	Performance   PerformanceConfig   `yaml:"performance" json:"performance"`
	Development   DevelopmentConfig   `yaml:"development" json:"development"`
	DHCPLeaseSync DHCPLeaseSyncConfig `yaml:"dhcp_lease_sync" json:"dhcp_lease_sync"`
}

// ClusterConfig holds file-based master/slave cluster settings.
type ClusterConfig struct {
	// Role is "master" or "slave". Default: "master" (standalone).
	Role string `yaml:"role" json:"role"`
	// Slaves is the list of slave node URLs (only used by master).
	Slaves []string `yaml:"slaves" json:"slaves"`
	// MasterURL is the master node URL (only used by slave).
	MasterURL string `yaml:"master_url" json:"master_url"`
	// PushTimeout is the timeout for push requests to slaves.
	PushTimeout Duration `yaml:"push_timeout" json:"push_timeout"`
	// PollInterval is how often slaves poll the master as fallback.
	PollInterval Duration `yaml:"poll_interval" json:"poll_interval"`
	// DataDir is the directory for JSON data files.
	DataDir string `yaml:"data_dir" json:"data_dir"`
	// SyncSecret is read from DOMUDNS_SYNC_SECRET env var.
	SyncSecret string `yaml:"-" json:"-"`
}

// BlocklistConfig holds blocked/allowed zone settings.
type BlocklistConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	FilePath      string   `yaml:"file_path" json:"file_path"`
	FetchInterval Duration `yaml:"fetch_interval" json:"fetch_interval"`
	BlockIP4      string   `yaml:"block_ip4" json:"block_ip4"`
	BlockIP6      string   `yaml:"block_ip6" json:"block_ip6"`
	// DefaultURLs: blocklist URLs automatically registered on first start,
	// when no URLs are present in the filestore. Only on master/standalone.
	DefaultURLs []string `yaml:"default_urls" json:"default_urls"`
	// BlockMode determines the DNS response for blocked domains.
	// "zero_ip"  (default): Returns 0.0.0.0 (A) or :: (AAAA).
	// "nxdomain": Returns NXDOMAIN — browser aborts immediately, no TLS timeout.
	BlockMode string `yaml:"block_mode" json:"block_mode"`
}

// ConditionalForward defines a domain-specific DNS forwarding rule.
// DNS queries for the given domain (and all its subdomains) are forwarded
// to the specified servers instead of the default upstream.
type ConditionalForward struct {
	// Domain is the zone to forward, e.g. "fritz.box" or "corp.internal".
	Domain string `yaml:"domain" json:"domain"`
	// Servers is the list of DNS servers to forward to (IP or FQDN, optional :port).
	Servers []string `yaml:"servers" json:"servers"`
}

// DoHConfig holds DNS over HTTPS (RFC 8484) server settings.
type DoHConfig struct {
	// Enabled activates the DoH endpoint (GET/POST /dns-query).
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Path is the HTTP path for DoH requests. Default: "/dns-query".
	Path string `yaml:"path" json:"path"`
}

// DoTConfig holds DNS over TLS (RFC 7858) server settings.
type DoTConfig struct {
	// Enabled activates the DoT listener on port 853.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Listen is the address for the DoT listener. Default: "[::]:853".
	Listen string `yaml:"listen" json:"listen"`
	// CertFile is the path to the TLS certificate. Empty = use caddy.tls.cert_file.
	CertFile string `yaml:"cert_file" json:"cert_file"`
	// KeyFile is the path to the TLS private key. Empty = use caddy.tls.key_file.
	KeyFile string `yaml:"key_file" json:"key_file"`
}

// AXFRConfig configures zone transfer (AXFR/IXFR, RFC 5936/1995).
type AXFRConfig struct {
	// Enabled activates zone transfer requests (AXFR/IXFR).
	Enabled bool `yaml:"enabled" json:"enabled"`
	// AllowedIPs is the whitelist of allowed client IPs/CIDRs.
	// Empty = reject all requests (secure default).
	AllowedIPs []string `yaml:"allowed_ips" json:"allowed_ips"`
}

// SplitHorizonView maps a view name to a set of CIDR ranges.
// Clients from these networks receive the view-specific zones.
type SplitHorizonView struct {
	// Name identifies the view (e.g. "internal", "external").
	Name string `yaml:"name" json:"name"`
	// Subnets is the list of CIDR ranges for this view (empty = catch-all).
	Subnets []string `yaml:"subnets" json:"subnets"`
}

// SplitHorizonConfig configures the split-horizon DNS feature.
type SplitHorizonConfig struct {
	// Enabled activates split-horizon DNS.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Views is the ordered list of views (first-match wins).
	Views []SplitHorizonView `yaml:"views" json:"views"`
}

// DNSServerConfig holds custom DNS server settings.
type DNSServerConfig struct {
	Listen              string               `yaml:"listen" json:"listen"`
	Upstream            []string             `yaml:"upstream" json:"upstream"`
	Cache               CacheConfig          `yaml:"cache" json:"cache"`
	UDPSize             int                  `yaml:"udp_size" json:"udp_size"`
	TCPTimeout          Duration             `yaml:"tcp_timeout" json:"tcp_timeout"`
	ConditionalForwards []ConditionalForward `yaml:"conditional_forwards" json:"conditional_forwards"`
	DoH                 DoHConfig            `yaml:"doh" json:"doh"`
	DoT                 DoTConfig            `yaml:"dot" json:"dot"`
	SplitHorizon        SplitHorizonConfig   `yaml:"split_horizon" json:"split_horizon"`
	AXFR                AXFRConfig           `yaml:"axfr" json:"axfr"`
}

// CacheConfig holds cache settings.
type CacheConfig struct {
	Enabled        bool `yaml:"enabled"          json:"enabled"`
	Size           int  `yaml:"size"             json:"size"`
	TTL            int  `yaml:"ttl"              json:"ttl"`
	NegativeTTL    int  `yaml:"negative_ttl"     json:"negative_ttl"`
	WarmupEnabled  bool `yaml:"warmup_enabled"   json:"warmup_enabled"`  // deprecated: use warmup_disabled
	WarmupDisabled bool `yaml:"warmup_disabled"  json:"warmup_disabled"` // set true to opt out of cache warming
	WarmupCount    int  `yaml:"warmup_count"     json:"warmup_count"`
}

// CaddyConfig holds Caddy web server settings.
type CaddyConfig struct {
	Listen      string           `yaml:"listen" json:"listen"`
	AdminListen string           `yaml:"admin_listen" json:"admin_listen"`
	Email       string           `yaml:"email" json:"email"`
	Acme        CaddyAcmeConfig  `yaml:"acme" json:"acme"`
	WebUI       CaddyWebUIConfig `yaml:"web_ui" json:"web_ui"`
	API         CaddyAPIConfig   `yaml:"api" json:"api"`
	TLS         CaddyTLSConfig   `yaml:"tls" json:"tls"`
}

// CaddyAcmeConfig holds ACME settings.
type CaddyAcmeConfig struct {
	Provider  string `yaml:"provider"`
	Staging   bool   `yaml:"staging"`
	Challenge string `yaml:"challenge"`
}

// CaddyWebUIConfig holds Web UI settings.
type CaddyWebUIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// CaddyAPIConfig holds API settings.
type CaddyAPIConfig struct {
	Enabled            bool     `yaml:"enabled"`
	BasePath           string   `yaml:"base_path"`
	CORSAllowedOrigins []string `yaml:"cors_allowed_origins"`
	// TrustProxy, when true, uses X-Real-IP or X-Forwarded-For for client IP.
	TrustProxy bool `yaml:"trust_proxy"`
}

// CaddyTLSConfig holds TLS protocol settings.
type CaddyTLSConfig struct {
	Protocols []string `yaml:"protocols"`
	// CertFile and KeyFile enable HTTPS when both are set.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// AcmeConfig holds ACME DNS-01 plugin settings.
type AcmeConfig struct {
	DNSProvider        string `yaml:"dns_provider"`
	PropagationTimeout int    `yaml:"propagation_timeout"`
	PollingInterval    int    `yaml:"polling_interval"`
	ChallengeTTL       int    `yaml:"challenge_ttl"`
}

// SystemConfig holds system-wide settings.
type SystemConfig struct {
	LogLevel  string                `yaml:"log_level" json:"log_level"`
	LogFormat string                `yaml:"log_format" json:"log_format"`
	Metrics   SystemMetricsConfig   `yaml:"metrics" json:"metrics"`
	RateLimit SystemRateLimitConfig `yaml:"rate_limit" json:"rate_limit"`
	Security  SystemSecurityConfig  `yaml:"security" json:"security"`
	QueryLog  QueryLogConfig        `yaml:"query_log" json:"query_log"`
}

// QueryLogConfig holds query log settings.
type QueryLogConfig struct {
	Enabled       bool   `yaml:"enabled" json:"enabled"`
	MemoryEntries int    `yaml:"memory_entries" json:"memory_entries"`
	PushInterval  string `yaml:"push_interval" json:"push_interval"`
	Persist       bool   `yaml:"persist" json:"persist"`
	PersistPath   string `yaml:"persist_path" json:"persist_path"`
	PersistDays   int    `yaml:"persist_days" json:"persist_days"`
}

// SystemMetricsConfig holds metrics settings.
type SystemMetricsConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Listen  string `yaml:"listen" json:"listen"`
}

// SystemRateLimitConfig holds rate limiting settings.
type SystemRateLimitConfig struct {
	Enabled     bool `yaml:"enabled" json:"enabled"`
	DNSQueries  int  `yaml:"dns_queries" json:"dns_queries"`
	APIRequests int  `yaml:"api_requests" json:"api_requests"`
}

// SystemSecurityConfig holds security settings.
type SystemSecurityConfig struct {
	DNSSEC             bool `yaml:"dnssec" json:"dnssec"`
	BlockAmplification bool `yaml:"block_amplification" json:"block_amplification"`
	// RebindingProtection blocks upstream responses that resolve public domains to
	// private/RFC1918 IPs (DNS rebinding attack against home routers).
	// Opt-in, default: false.
	RebindingProtection bool `yaml:"rebinding_protection" json:"rebinding_protection"`
	// RebindingProtectionWhitelist contains domain suffixes excluded from the check
	// (e.g. "fritz.box", "corp.internal").
	RebindingProtectionWhitelist []string `yaml:"rebinding_protection_whitelist" json:"rebinding_protection_whitelist"`
}

// PerformanceConfig holds performance tuning settings.
type PerformanceConfig struct {
	DNSTimeout Duration `yaml:"dns_timeout"`
	APITimeout Duration `yaml:"api_timeout"`
}

// DevelopmentConfig holds development/debug settings.
type DevelopmentConfig struct {
	Debug       bool   `yaml:"debug"`
	Pprof       bool   `yaml:"pprof"`
	PprofListen string `yaml:"pprof_listen"`
}

// Load reads and parses the configuration from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyDefaults(&cfg)
	return &cfg, nil
}

// MergeOverrides applies overrides from the file store into cfg.
func MergeOverrides(cfg *Config, overrides map[string]interface{}) error {
	if len(overrides) == 0 {
		return nil
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("unmarshal config to map: %w", err)
	}
	merged := mergeMap(m, overrides)
	mergedData, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal merged config: %w", err)
	}
	if err := json.Unmarshal(mergedData, cfg); err != nil {
		return fmt.Errorf("unmarshal merged config: %w", err)
	}
	applyDefaults(cfg)
	return nil
}

func mergeMap(dst, src map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = make(map[string]interface{})
	}
	for k, v := range src {
		if v == nil {
			continue
		}
		if srcMap, ok := v.(map[string]interface{}); ok {
			var dstMap map[string]interface{}
			if dstV, exists := dst[k]; exists {
				if m, ok := dstV.(map[string]interface{}); ok {
					dstMap = m
				}
			}
			if dstMap == nil {
				dstMap = make(map[string]interface{})
			}
			dst[k] = mergeMap(dstMap, srcMap)
		} else {
			dst[k] = v
		}
	}
	return dst
}

func applyDefaults(cfg *Config) {
	if cfg.DNSServer.Listen == "" {
		cfg.DNSServer.Listen = "[::]:53"
	}
	if cfg.Caddy.Listen == "" {
		cfg.Caddy.Listen = "0.0.0.0:80"
	}
	if cfg.Caddy.AdminListen == "" {
		cfg.Caddy.AdminListen = "127.0.0.1:2019"
	}
	if cfg.Caddy.API.BasePath == "" {
		cfg.Caddy.API.BasePath = "/api"
	}
	if cfg.System.LogLevel == "" {
		cfg.System.LogLevel = "info"
	}
	if cfg.System.LogFormat == "" {
		cfg.System.LogFormat = "json"
	}
	if cfg.DNSServer.UDPSize == 0 {
		cfg.DNSServer.UDPSize = 4096
	}
	if cfg.DNSServer.DoH.Path == "" {
		cfg.DNSServer.DoH.Path = "/dns-query"
	}
	if cfg.DNSServer.DoT.Listen == "" {
		cfg.DNSServer.DoT.Listen = "[::]:853"
	}
	if cfg.DNSServer.TCPTimeout == 0 {
		cfg.DNSServer.TCPTimeout = Duration(5 * time.Second)
	}
	if len(cfg.DNSServer.Upstream) == 0 {
		cfg.DNSServer.Upstream = []string{"1.1.1.1", "8.8.8.8"}
	}
	if cfg.Blocklist.FilePath == "" {
		cfg.Blocklist.FilePath = "/var/lib/dns-stack/blocklist.hosts"
	}
	if cfg.Blocklist.FetchInterval == 0 {
		cfg.Blocklist.FetchInterval = Duration(24 * time.Hour)
	}
	if cfg.Blocklist.BlockIP4 == "" {
		cfg.Blocklist.BlockIP4 = "0.0.0.0"
	}
	if cfg.Blocklist.BlockIP6 == "" {
		cfg.Blocklist.BlockIP6 = "::"
	}
	if cfg.Blocklist.BlockMode == "" {
		cfg.Blocklist.BlockMode = "zero_ip"
	}

	// Cluster defaults
	if cfg.Cluster.Role == "" {
		cfg.Cluster.Role = "master"
	}
	if cfg.Cluster.PushTimeout == 0 {
		cfg.Cluster.PushTimeout = Duration(5 * time.Second)
	}
	if cfg.Cluster.PollInterval == 0 {
		cfg.Cluster.PollInterval = Duration(30 * time.Second)
	}
	if cfg.Cluster.DataDir == "" {
		cfg.Cluster.DataDir = "/var/lib/dns-stack/data"
	}

	// Env vars override YAML — so each node can read its role from /etc/dns-stack/env
	// without needing a node-specific config.yaml.
	if role := os.Getenv("DOMUDNS_CLUSTER_ROLE"); role == "master" || role == "slave" {
		cfg.Cluster.Role = role
	}
	if masterURL := os.Getenv("DOMUDNS_CLUSTER_MASTER_URL"); masterURL != "" {
		cfg.Cluster.MasterURL = masterURL
	}
	if slaves := os.Getenv("DOMUDNS_CLUSTER_SLAVES"); slaves != "" {
		// Comma-separated list: "http://pi2:80,http://pi3:80"
		parts := strings.Split(slaves, ",")
		cfg.Cluster.Slaves = make([]string, 0, len(parts))
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				cfg.Cluster.Slaves = append(cfg.Cluster.Slaves, s)
			}
		}
	}
	if secret := os.Getenv("DOMUDNS_SYNC_SECRET"); secret != "" {
		cfg.Cluster.SyncSecret = secret
	}

	// Cache-Warmup Defaults
	if cfg.DNSServer.Cache.WarmupCount == 0 {
		cfg.DNSServer.Cache.WarmupCount = 200
	}

	// DHCP-Lease-Sync Defaults
	if cfg.DHCPLeaseSync.TTL == 0 {
		cfg.DHCPLeaseSync.TTL = 60
	}
	if cfg.DHCPLeaseSync.PollInterval == 0 {
		cfg.DHCPLeaseSync.PollInterval = Duration(30 * time.Second)
	}
	if pw := os.Getenv("DOMUDNS_FRITZBOX_PASSWORD"); pw != "" {
		cfg.DHCPLeaseSync.FritzBoxPassword = pw
	}
}
