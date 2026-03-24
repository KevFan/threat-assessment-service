package scoring

import (
	"strings"
)

// Scorer evaluates a request and returns a threat score with reasons.
type Scorer struct {
	blacklist map[string]bool
}

// NewScorer creates a Scorer with the given blacklisted IPs.
func NewScorer(blacklistedIPs []string) *Scorer {
	bl := make(map[string]bool, len(blacklistedIPs))
	for _, ip := range blacklistedIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			bl[ip] = true
		}
	}
	return &Scorer{blacklist: bl}
}

// Score evaluates a request and returns total threat level and reasons.
func (s *Scorer) Score(uri string, isAuthenticated bool, sourceIP string) (int32, []string) {
	var level int32
	var reasons []string

	// Rule 1: unauthenticated request +1
	if !isAuthenticated {
		level += 1
		reasons = append(reasons, "unauthenticated")
	}

	// Rule 2: blacklisted IP +5
	if s.blacklist[sourceIP] {
		level += 5
		reasons = append(reasons, "blacklisted_ip")
	}

	// Rule 3: path traversal attempt +4
	if strings.Contains(uri, "../") || strings.Contains(uri, `..\`) {
		level += 4
		reasons = append(reasons, "path_traversal_attempt")
	}

	// Rule 4: admin path without auth +3
	if strings.HasPrefix(uri, "/admin") && !isAuthenticated {
		level += 3
		reasons = append(reasons, "admin_path_unauthenticated")
	}

	return level, reasons
}
