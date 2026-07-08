package dynamicproxy

import (
	"net/http"
	"regexp"
	"strings"
)

/*
	pathpolicy.go

	This script handles per-path policy rules on proxy endpoints.
	A path policy can enforce an access rule (IP/CIDR/GeoIP white/blacklist)
	and/or require the endpoint's authentication provider on matching paths.
*/

// MatchPathPolicyRule returns the first enabled path policy rule that matches
// the request path, or nil if no rule matches
func (ep *ProxyEndpoint) MatchPathPolicyRule(r *http.Request) *PathPolicyRule {
	for _, rule := range ep.PathPolicyRules {
		if rule == nil || !rule.Enabled {
			continue
		}
		if rule.IsRegex {
			matched, err := regexp.MatchString(rule.PathPattern, r.URL.Path)
			if err == nil && matched {
				return rule
			}
		} else if strings.HasPrefix(r.URL.Path, rule.PathPattern) {
			return rule
		}
	}
	return nil
}

// handlePathPolicyAccess enforces the access-rule half of a matched path policy.
// Returns true if the request was blocked (response already written).
func (h *ProxyHandler) handlePathPolicyAccess(rule *PathPolicyRule, w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	if rule == nil || rule.AccessRuleID == "" {
		return false
	}
	return h.handleAccessRouting(rule.AccessRuleID, w, r, sep)
}
