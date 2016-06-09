// Copyright 2016 The Linux Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lib

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func (of *OCIFetcher) acquireAuthToken(client *http.Client, wwwAuthenticate, repo, registryHost string) error {
	tokens := strings.Split(wwwAuthenticate, ",")
	if len(tokens) != 3 ||
		!strings.HasPrefix(strings.ToLower(tokens[0]), "bearer realm") {
		return fmt.Errorf("couldn't parse WWW-Authenticate header: %q", wwwAuthenticate)
	}

	var realm, service, scope string
	for _, token := range tokens {
		if strings.HasPrefix(strings.ToLower(token), "bearer realm") {
			realm = strings.Trim(token[len("bearer realm="):], "\"")
		}
		if strings.HasPrefix(token, "service") {
			service = strings.Trim(token[len("service="):], "\"")
		}
		if strings.HasPrefix(token, "scope") {
			scope = strings.Trim(token[len("scope="):], "\"")
		}
	}

	if realm == "" {
		return fmt.Errorf("missing realm in bearer auth challenge")
	}
	if service == "" {
		return fmt.Errorf("missing service in bearer auth challenge")
	}
	// The scope can be empty if we're not getting a token for a specific repo
	if scope == "" && repo != "" {
		// If the scope is empty and it shouldn't be, we can infer it based on the repo
		scope = fmt.Sprintf("repository:%s:pull", repo)
	}

	authReq, err := http.NewRequest("GET", realm, nil)
	if err != nil {
		return err
	}

	getParams := authReq.URL.Query()
	getParams.Add("service", service)
	if scope != "" {
		getParams.Add("scope", scope)
	}
	authReq.URL.RawQuery = getParams.Encode()

	of.setBasicAuth(authReq)

	of.debugMsg("requesting auth token with: %s", authReq.URL.String())

	res, err := client.Do(authReq)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("unable to retrieve auth token: 401 unauthorized")
	case http.StatusOK:
		break
	default:
		return fmt.Errorf("unexpected http code: %d, URL: %s", res.StatusCode, authReq.URL)
	}

	tokenBlob, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	tokenStruct := struct {
		Token string `json:"token"`
	}{}

	err = json.Unmarshal(tokenBlob, &tokenStruct)
	if err != nil {
		return err
	}

	hostAuthTokens, ok := of.hostsV2AuthTokens[registryHost]
	if !ok {
		hostAuthTokens = make(map[string]string)
		of.hostsV2AuthTokens[registryHost] = hostAuthTokens
	}

	hostAuthTokens[repo] = tokenStruct.Token

	of.debugMsg("successfully retrieved auth token")

	return nil
}

func (of *OCIFetcher) setBasicAuth(req *http.Request) {
	if of.username != "" && of.password != "" {
		req.SetBasicAuth(of.username, of.password)
	}
}
