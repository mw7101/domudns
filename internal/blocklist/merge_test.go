package blocklist

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMerge_Empty(t *testing.T) {
	assert.Empty(t, Merge(nil, nil))
	assert.Empty(t, Merge([]string{}, []string{}))
}

func TestMerge_NoAllowed(t *testing.T) {
	blocked := []string{"evil.com", "ads.evil.com"}
	result := Merge(blocked, nil)
	assert.ElementsMatch(t, blocked, result)
}

func TestMerge_ExactMatchAllowed(t *testing.T) {
	blocked := []string{"evil.com", "ads.evil.com"}
	allowed := []string{"ads.evil.com"}
	result := Merge(blocked, allowed)
	assert.Equal(t, []string{"evil.com"}, result)
}

func TestMerge_SubdomainAllowed(t *testing.T) {
	blocked := []string{"evil.com", "ads.evil.com", "x.evil.com"}
	allowed := []string{"evil.com"}
	result := Merge(blocked, allowed)
	assert.Empty(t, result) // evil.com and *.evil.com are allowed
}

func TestMerge_PartialAllow(t *testing.T) {
	blocked := []string{"a.com", "b.com", "c.com"}
	allowed := []string{"b.com"}
	result := Merge(blocked, allowed)
	assert.ElementsMatch(t, []string{"a.com", "c.com"}, result)
}
