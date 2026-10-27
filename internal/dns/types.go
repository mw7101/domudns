package dns

// ClientGroup maps a set of CIDR ranges to a list of active blocklist categories.
// Stored as client_groups.json in the data directory.
type ClientGroup struct {
	Name       string   `json:"name"`       // unique identifier, e.g. "kids"
	CIDRs      []string `json:"cidrs"`      // e.g. ["192.168.2.0/24"]
	Categories []string `json:"categories"` // active categories, e.g. ["ads","malware","adult"]
}
