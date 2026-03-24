package scoring

import (
	"testing"
)

func TestScorer(t *testing.T) {
	blacklist := []string{"192.0.2.100", "203.0.113.50", "198.51.100.25"}
	scorer := NewScorer(blacklist)

	tests := []struct {
		name            string
		uri             string
		isAuthenticated bool
		sourceIP        string
		wantLevel       int32
		wantReasons     []string
	}{
		{
			name:            "clean request",
			uri:             "/users",
			isAuthenticated: true,
			sourceIP:        "10.0.0.1",
			wantLevel:       0,
			wantReasons:     nil,
		},
		{
			name:            "unauthenticated request",
			uri:             "/users",
			isAuthenticated: false,
			sourceIP:        "10.0.0.1",
			wantLevel:       1,
			wantReasons:     []string{"unauthenticated"},
		},
		{
			name:            "blacklisted IP",
			uri:             "/users",
			isAuthenticated: false,
			sourceIP:        "192.0.2.100",
			wantLevel:       6,
			wantReasons:     []string{"unauthenticated", "blacklisted_ip"},
		},
		{
			name:            "path traversal attempt",
			uri:             "/../../etc/passwd",
			isAuthenticated: false,
			sourceIP:        "10.0.0.1",
			wantLevel:       5,
			wantReasons:     []string{"unauthenticated", "path_traversal_attempt"},
		},
		{
			name:            "unauthenticated admin access",
			uri:             "/admin/users",
			isAuthenticated: false,
			sourceIP:        "10.0.0.1",
			wantLevel:       4,
			wantReasons:     []string{"unauthenticated", "admin_path_unauthenticated"},
		},
		{
			name:            "authenticated admin access",
			uri:             "/admin/settings",
			isAuthenticated: true,
			sourceIP:        "10.0.0.1",
			wantLevel:       0,
			wantReasons:     nil,
		},
		{
			name:            "blacklisted IP authenticated",
			uri:             "/users",
			isAuthenticated: true,
			sourceIP:        "203.0.113.50",
			wantLevel:       5,
			wantReasons:     []string{"blacklisted_ip"},
		},
		{
			name:            "path traversal with backslash",
			uri:             `/foo/..\bar`,
			isAuthenticated: true,
			sourceIP:        "10.0.0.1",
			wantLevel:       4,
			wantReasons:     []string{"path_traversal_attempt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLevel, gotReasons := scorer.Score(tt.uri, tt.isAuthenticated, tt.sourceIP)
			if gotLevel != tt.wantLevel {
				t.Errorf("threat level = %d, want %d", gotLevel, tt.wantLevel)
			}
			if len(gotReasons) != len(tt.wantReasons) {
				t.Errorf("reasons = %v, want %v", gotReasons, tt.wantReasons)
				return
			}
			for i, r := range gotReasons {
				if r != tt.wantReasons[i] {
					t.Errorf("reasons[%d] = %q, want %q", i, r, tt.wantReasons[i])
				}
			}
		})
	}
}

func TestNewScorerTrimsWhitespace(t *testing.T) {
	scorer := NewScorer([]string{"  192.0.2.100  ", "", "  "})
	level, _ := scorer.Score("/", false, "192.0.2.100")
	if level != 6 {
		t.Errorf("expected level 6, got %d", level)
	}
}
