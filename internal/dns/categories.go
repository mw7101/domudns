package dns

// Blocklist category constants. The empty string ("") means uncategorized —
// always active for all clients regardless of group.
const (
	CategoryAds      = "ads"
	CategoryMalware  = "malware"
	CategoryAdult    = "adult"
	CategorySocial   = "social"
	CategoryGambling = "gambling"
	CategoryTracking = "tracking"
)

// ValidCategories is the set of allowed category values for validation.
var ValidCategories = map[string]struct{}{
	CategoryAds:      {},
	CategoryMalware:  {},
	CategoryAdult:    {},
	CategorySocial:   {},
	CategoryGambling: {},
	CategoryTracking: {},
}

// DefaultCategories returns the default active categories when a client matches no group.
// A new slice is returned on every call to prevent callers from mutating the global default.
func DefaultCategories() []string {
	return []string{CategoryAds, CategoryMalware}
}
