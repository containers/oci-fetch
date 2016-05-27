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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/opencontainers/oci-fetch/lib/schema"
)

type OCIFetcher struct {
	username                    string
	password                    string
	hostsV2AuthTokens           map[string]map[string]string
	insecureAllowHTTP           bool
	insecureSkipTLSVerification bool
	debug                       bool
}

func NewOCIFetcher(username, password string, insecureAllowHTTP, insecureSkipTLSVerification, debug bool) *OCIFetcher {
	return &OCIFetcher{
		username:                    username,
		password:                    password,
		hostsV2AuthTokens:           make(map[string]map[string]string),
		insecureAllowHTTP:           insecureAllowHTTP,
		insecureSkipTLSVerification: insecureSkipTLSVerification,
		debug: debug,
	}
}

func (of *OCIFetcher) debugMsg(format string, a ...interface{}) {
	if of.debug {
		out := fmt.Sprintf(format, a...)
		fmt.Fprintln(os.Stderr, strings.TrimSuffix(out, "\n"))
	}
}

func (of *OCIFetcher) Fetch(u *URL, outputDir string) error {
	of.debugMsg("fetching OCI image %q", u.String())
	manifest, err := of.fetchManifest(u)
	if err != nil {
		return err
	}
	of.debugMsg("manifest successfully retrieved")
	config, err := of.fetchConfig(u, manifest.Config.Digest, manifest.Config.Size)
	if err != nil {
		return err
	}
	of.debugMsg("config successfully retrieved")
	var doneChans []chan error
	for _, layer := range manifest.Layers {
		layer := layer
		doneChan := make(chan error, 1)
		doneChans = append(doneChans, doneChan)
		go func() {
			doneChan <- of.fetchLayer(u, layer.Digest, layer.Size, outputDir)
		}()
	}
	for _, doneChan := range doneChans {
		if err := <-doneChan; err != nil {
			return err
		}
	}
	of.debugMsg("layers successfully retrieved")

	err = writeJSONToFile(path.Join(outputDir, "manifest.json"), manifest)
	if err != nil {
		return err
	}
	err = writeJSONToFile(path.Join(outputDir, manifest.Config.Digest+".json"), config)
	if err != nil {
		return err
	}
	return nil
}

func writeJSONToFile(path string, data interface{}) error {
	blob, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, blob, 0644)
}

func (of *OCIFetcher) fetchManifest(u *URL) (*schema.ImageManifest, error) {
	stringURL := "https://" + path.Join(u.Host, "v2", u.Name, "manifests", u.Version)

	req, err := http.NewRequest("GET", stringURL, nil)
	if err != nil {
		return nil, err
	}

	of.setBasicAuth(req)

	res, err := of.makeRequest(req, u.Name, schema.MediaTypeManifest)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected http code: %d, URL: %s", res.StatusCode, req.URL)
	}

	manblob, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	manifest := &schema.ImageManifest{}

	err = json.Unmarshal(manblob, manifest)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Parsed manifest: %s\n", manifest.PrettyString())

	return manifest, manifest.Validate()
}

func (of *OCIFetcher) fetchConfig(u *URL, configDigest string, expectedSize int) (*schema.ImageConfig, error) {
	stringURL := "http://" + path.Join(u.Host, "v2", u.Name, "blobs", configDigest)

	req, err := http.NewRequest("GET", stringURL, nil)
	if err != nil {
		return nil, err
	}

	of.setBasicAuth(req)

	res, err := of.makeRequest(req, u.Name, schema.MediaTypeConfig)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected http code: %d, URL: %s", res.StatusCode, req.URL)
	}

	confblob, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Unparsed config: %s\n", string(confblob))

	if len(confblob) != expectedSize {
		return nil, fmt.Errorf("retrieved image config didn't match expected size, expected=%d actual=%d", expectedSize, len(confblob))
	}

	config := &schema.ImageConfig{}

	err = json.Unmarshal(confblob, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
func (of *OCIFetcher) fetchLayer(u *URL, layerDigest string, expectedSize int, outputDir string) error {
	stringURL := "http://" + path.Join(u.Host, "v2", u.Name, "blobs", layerDigest)

	req, err := http.NewRequest("GET", stringURL, nil)
	if err != nil {
		return err
	}

	of.setBasicAuth(req)

	res, err := of.makeRequest(req, u.Name, schema.MediaTypeRootFS)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http code: %d, URL: %s", res.StatusCode, req.URL)
	}

	err = os.MkdirAll(path.Join(outputDir, layerDigest), 0755)
	if err != nil {
		return err
	}
	f, err := os.Create(path.Join(outputDir, layerDigest, "layer.tar"))
	if err != nil {
		return err
	}
	size, err := io.Copy(f, res.Body)
	if err != nil {
		return err
	}

	if size != int64(expectedSize) {
		return fmt.Errorf("retrieved image layer didn't match expected size, expected=%d actual=%d", expectedSize, size)
	}

	return nil
}

func (of *OCIFetcher) makeRequest(req *http.Request, repo string, mediaType string) (*http.Response, error) {
	setBearerHeader := false
	hostAuthTokens, ok := of.hostsV2AuthTokens[req.URL.Host]
	if ok {
		authToken, ok := hostAuthTokens[repo]
		if ok {
			fmt.Println("setting bearer token on request")
			fmt.Println("Bearer " + authToken)
			req.Header.Set("Authorization", "Bearer "+authToken)
			setBearerHeader = true
		}
	}

	req.Header.Set("Accept", mediaType)

	of.debugMsg("making request to: %s", req.URL.String())

	client := GetTLSClient(of.insecureSkipTLSVerification)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode == http.StatusUnauthorized && setBearerHeader {
		return res, nil
	}

	hdr := res.Header.Get("www-authenticate")
	if res.StatusCode != http.StatusUnauthorized || hdr == "" {
		return res, nil
	}

	of.debugMsg("need to get auth token: %s", hdr)

	of.acquireAuthToken(client, hdr, repo, req.URL.Host)

	return of.makeRequest(req, repo, mediaType)
}

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

	of.debugMsg("requesting auth token with: ", authReq.URL.String())

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

// GetTLSClient gets an HTTP client that behaves like the default HTTP
// client, but optionally skips the TLS certificate verification.
func GetTLSClient(skipTLSCheck bool) *http.Client {
	if !skipTLSCheck {
		return http.DefaultClient
	}
	client := *http.DefaultClient
	// Default transport is hidden behind the RoundTripper
	// interface, so we can't easily make a copy of it. If this
	// ever panics, we will have to adapt.
	realTransport := http.DefaultTransport.(*http.Transport)
	tr := *realTransport
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.InsecureSkipVerify = true
	client.Transport = &tr
	return &client
}
