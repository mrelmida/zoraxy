package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/tlscert"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	rawconfig.go

	API handlers for viewing and editing the raw JSON config of a proxy endpoint.
	This is an advanced escape hatch that exposes every field of the ProxyEndpoint
	struct, including ones without dedicated UI controls.
*/

// HandleRawProxyConfig serves (GET) or applies (POST) the raw JSON config of
// a proxy endpoint. Use ep=root for the default site.
func HandleRawProxyConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleRawProxyConfigGet(w, r)
	case http.MethodPost:
		handleRawProxyConfigSet(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func loadProxyOrRoot(ep string) (*dynamicproxy.ProxyEndpoint, error) {
	if ep == "root" || ep == "/" {
		root := dynamicProxyRouter.Root
		if root == nil {
			return nil, os.ErrNotExist
		}
		return root, nil
	}
	return dynamicProxyRouter.LoadProxy(ep)
}

func handleRawProxyConfigGet(w http.ResponseWriter, r *http.Request) {
	ep, err := utils.GetPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "Invalid ep given")
		return
	}

	targetProxy, err := loadProxyOrRoot(ep)
	if err != nil {
		utils.SendErrorResponse(w, "Target proxy config not found")
		return
	}

	copied := dynamicproxy.CopyEndpoint(targetProxy)
	js, err := json.MarshalIndent(copied, "", " ")
	if err != nil {
		utils.SendErrorResponse(w, "Unable to serialize config: "+err.Error())
		return
	}
	utils.SendJSONResponse(w, string(js))
}

func handleRawProxyConfigSet(w http.ResponseWriter, r *http.Request) {
	ep, err := utils.PostPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "Invalid ep given")
		return
	}

	configStr, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "Invalid config given")
		return
	}

	existingProxy, err := loadProxyOrRoot(ep)
	if err != nil {
		utils.SendErrorResponse(w, "Target proxy config not found")
		return
	}

	//Decode over a default-initialized endpoint so omitted fields get defaults.
	//Unknown fields are rejected so typos surface as errors instead of being dropped.
	newEndpoint := dynamicproxy.GetDefaultProxyEndpoint()
	decoder := json.NewDecoder(strings.NewReader(configStr))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&newEndpoint); err != nil {
		utils.SendErrorResponse(w, "JSON error: "+err.Error())
		return
	}

	//Renaming or retyping an endpoint through the raw editor would orphan the
	//old config file on disk, so both are rejected here
	if newEndpoint.RootOrMatchingDomain != existingProxy.RootOrMatchingDomain {
		utils.SendErrorResponse(w, "Changing RootOrMatchingDomain is not supported in the raw editor")
		return
	}
	if newEndpoint.ProxyType != existingProxy.ProxyType {
		utils.SendErrorResponse(w, "Changing ProxyType is not supported in the raw editor")
		return
	}

	//Nil-fix optional sections, mirroring LoadReverseProxyConfig
	if newEndpoint.Tags == nil {
		newEndpoint.Tags = []string{}
	}
	if newEndpoint.TlsOptions == nil {
		newEndpoint.TlsOptions = tlscert.GetDefaultHostSpecificTlsBehavior()
	}
	if newEndpoint.PathPolicyRules == nil {
		newEndpoint.PathPolicyRules = []*dynamicproxy.PathPolicyRule{}
	}
	if newEndpoint.AuthenticationProvider == nil {
		newEndpoint.AuthenticationProvider = &dynamicproxy.AuthenticationProvider{
			AuthMethod:              dynamicproxy.AuthMethodNone,
			BasicAuthCredentials:    []*dynamicproxy.BasicAuthCredentials{},
			BasicAuthExceptionRules: []*dynamicproxy.BasicAuthExceptionRule{},
		}
	}

	//Prepare the new route. This performs the semantic validation (builds the
	//proxy instances, compiles the exploit detector, etc.)
	readyEndpoint, err := dynamicProxyRouter.PrepareProxyRoute(&newEndpoint)
	if err != nil {
		utils.SendErrorResponse(w, "Config validation failed: "+err.Error())
		return
	}

	if newEndpoint.ProxyType == dynamicproxy.ProxyTypeRoot {
		dynamicProxyRouter.SetProxyRouteAsRoot(readyEndpoint)
	} else {
		existingProxy.Remove()
		loadBalancer.ResetSessions()
		dynamicProxyRouter.AddProxyRouteToRuntime(readyEndpoint)
	}

	if err := SaveReverseProxyConfig(&newEndpoint); err != nil {
		utils.SendErrorResponse(w, "Config applied but could not be saved: "+err.Error())
		return
	}
	//Pick up any ListeningPorts changes
	dynamicProxyRouter.UpdateSecondaryListeners()
	UpdateUptimeMonitorTargets()
	utils.SendOK(w)
}

// HandleReloadProxyConfigFromDisk re-reads an endpoint's .config file from disk
// and applies it to the runtime, so hand-edited files take effect without a restart
func HandleReloadProxyConfigFromDisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ep, err := utils.PostPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "Invalid ep given")
		return
	}

	existingProxy, err := loadProxyOrRoot(ep)
	if err != nil {
		utils.SendErrorResponse(w, "Target proxy config not found")
		return
	}

	filename := filepath.Join(CONF_HTTP_PROXY, existingProxy.RootOrMatchingDomain+".config")
	if existingProxy.ProxyType == dynamicproxy.ProxyTypeRoot {
		filename = filepath.Join(CONF_HTTP_PROXY, "root.config")
	}
	filename = filterProxyConfigFilename(filename)
	if !utils.FileExists(filename) {
		utils.SendErrorResponse(w, "Config file not found on disk: "+filename)
		return
	}

	if existingProxy.ProxyType != dynamicproxy.ProxyTypeRoot {
		existingProxy.Remove()
		loadBalancer.ResetSessions()
	}
	if err := LoadReverseProxyConfig(filename); err != nil {
		utils.SendErrorResponse(w, "Unable to reload config: "+err.Error())
		return
	}
	//Pick up any ListeningPorts changes
	dynamicProxyRouter.UpdateSecondaryListeners()
	UpdateUptimeMonitorTargets()
	utils.SendOK(w)
}
