package blocklist

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseHostsOrDomains_HostsFormat(t *testing.T) {
	content := `# comment
0.0.0.0 ads.example.com
0.0.0.0 tracking.evil.org
127.0.0.1 localhost
`
	domains := ParseHostsOrDomains(content)
	assert.Contains(t, domains, "ads.example.com")
	assert.Contains(t, domains, "tracking.evil.org")
	assert.NotContains(t, domains, "localhost")
	assert.Len(t, domains, 2)
}

func TestParseHostsOrDomains_DomainsFormat(t *testing.T) {
	content := `malware.com
tracking.org
`
	domains := ParseHostsOrDomains(content)
	assert.Contains(t, domains, "malware.com")
	assert.Contains(t, domains, "tracking.org")
	assert.Len(t, domains, 2)
}

func TestParseHostsOrDomains_AdblockFormat(t *testing.T) {
	content := `||evil.com^
||ads.example.com^
`
	domains := ParseHostsOrDomains(content)
	assert.Contains(t, domains, "evil.com")
	assert.Contains(t, domains, "ads.example.com")
	assert.Len(t, domains, 2)
}

func TestParseHostsOrDomains_EmptyAndComments(t *testing.T) {
	content := `
# only comment

`
	domains := ParseHostsOrDomains(content)
	assert.Empty(t, domains)
}
