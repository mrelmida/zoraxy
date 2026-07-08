package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	pathpolicy.go

	API handlers for per-path policy rules on proxy endpoints.
	A path policy can enforce an access rule and/or require authentication
	on paths matching a prefix or regex pattern.
*/

// HandleListPathPolicyRules lists all path policy rules of a proxy endpoint
func HandleListPathPolicyRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ep, err := utils.GetPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "Invalid ep given")
		return
	}

	targetProxy, err := dynamicProxyRouter.LoadProxy(ep)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	results := targetProxy.PathPolicyRules
	if results == nil {
		results = []*dynamicproxy.PathPolicyRule{}
	}
	js, _ := json.Marshal(results)
	utils.SendJSONResponse(w, string(js))
}

// HandleSetPathPolicyRules replaces the full ordered list of path policy rules
// of a proxy endpoint. Ordering matters (first match wins), so the whole list
// is set atomically instead of piecemeal add/remove.
func HandleSetPathPolicyRules(w http.ResponseWriter, r *http.Request) {
	ep, err := utils.PostPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "Invalid ep given")
		return
	}

	rulesJSON, err := utils.PostPara(r, "rules")
	if err != nil {
		utils.SendErrorResponse(w, "Invalid rules given")
		return
	}

	targetProxy, err := dynamicProxyRouter.LoadProxy(ep)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	newRules := []*dynamicproxy.PathPolicyRule{}
	if err := json.Unmarshal([]byte(rulesJSON), &newRules); err != nil {
		utils.SendErrorResponse(w, "Unable to parse rules: "+err.Error())
		return
	}

	//Validate all rules before applying any of them
	for _, rule := range newRules {
		if rule == nil {
			utils.SendErrorResponse(w, "Invalid rule in rule list")
			return
		}
		rule.PathPattern = strings.TrimSpace(rule.PathPattern)
		if rule.PathPattern == "" {
			utils.SendErrorResponse(w, "Path pattern cannot be empty")
			return
		}
		if rule.IsRegex {
			if _, err := regexp.Compile(rule.PathPattern); err != nil {
				utils.SendErrorResponse(w, "Invalid regex pattern \""+rule.PathPattern+"\": "+err.Error())
				return
			}
		} else if !strings.HasPrefix(rule.PathPattern, "/") {
			rule.PathPattern = "/" + rule.PathPattern
		}
		if rule.AccessRuleID != "" && !accessController.AccessRuleExists(rule.AccessRuleID) {
			utils.SendErrorResponse(w, "Access rule not found: "+rule.AccessRuleID)
			return
		}
		if rule.ID == "" {
			rule.ID = uuid.New().String()
		}
	}

	//Build the slice fully, then assign in a single store
	targetProxy.PathPolicyRules = newRules
	targetProxy.UpdateToRuntime()
	err = SaveReverseProxyConfig(targetProxy)
	if err != nil {
		utils.SendErrorResponse(w, "Unable to save config: "+err.Error())
		return
	}
	utils.SendOK(w)
}
