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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/pkg/progressutil"
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

func blobsDir(outputDir string) string {
	return path.Join(outputDir, "blobs")
}

func blobFile(outputDir string, digest string) string {
	formattedDigest := strings.Replace(digest, ":", "-", -1)
	return path.Join(blobsDir(outputDir), formattedDigest)
}

func refsDir(outputDir string) string {
	return path.Join(outputDir, "refs")
}

func (of *OCIFetcher) Fetch(u *URL, outputDir string) error {
	of.debugMsg("fetching OCI image host:%s, name:%s, tag:%s", u.Host, u.Name, u.Version)
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

	cpp := &progressutil.CopyProgressPrinter{}
	layers := removeDuplicateLayers(manifest.Layers)

	var doneChans []chan error
	var closerChans []chan []io.Closer
	for _, layer := range layers {
		layer := layer
		doneChan := make(chan error, 1)
		doneChans = append(doneChans, doneChan)
		closerChan := make(chan []io.Closer, 1)
		closerChans = append(closerChans, closerChan)
		go func() {
			closers, err := of.fetchLayer(u, layer.Digest, layer.Size, outputDir, cpp)
			closerChan <- closers
			doneChan <- err
		}()
	}
	defer func() {
		for _, closerChan := range closerChans {
			closers := <-closerChan
			for _, closer := range closers {
				closer.Close()
			}
		}
	}()
	for _, doneChan := range doneChans {
		if err := <-doneChan; err != nil {
			return err
		}
	}
	err = cpp.PrintAndWait(os.Stderr, time.Second, nil)
	if err != nil {
		return err
	}
	of.debugMsg("layers successfully retrieved")

	err = writeJSONToFile(path.Join(outputDir, "oci-layout"), schema.DefaultOCILayout)
	if err != nil {
		return err
	}

	err = os.MkdirAll(path.Join(outputDir, "refs"), 0755)
	if err != nil {
		return err
	}
	err = writeJSONToFile(path.Join(outputDir, "refs", u.Version), manifest)
	if err != nil {
		return err
	}
	err = writeBlobFromJSON(outputDir, manifest.Config.Digest, config)
	if err != nil {
		return err
	}
	return nil
}

func removeDuplicateLayers(layers []*schema.ImageManifestDigest) []*schema.ImageManifestDigest {
	var uniqueLayers []*schema.ImageManifestDigest
	for _, layer := range layers {
		seen := false
		for _, seenLayer := range uniqueLayers {
			if seenLayer.Digest == layer.Digest {
				seen = true
			}
		}
		if !seen {
			uniqueLayers = append(uniqueLayers, layer)
		}
	}
	return uniqueLayers
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

	return manifest, manifest.Validate()
}

func (of *OCIFetcher) fetchConfig(u *URL, configDigest string, expectedSize int) (*schema.ImageConfig, error) {
	stringURL := "https://" + path.Join(u.Host, "v2", u.Name, "blobs", configDigest)

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
func (of *OCIFetcher) fetchLayer(u *URL, layerDigest string, expectedSize int, outputDir string, cpp *progressutil.CopyProgressPrinter) ([]io.Closer, error) {
	stringURL := "https://" + path.Join(u.Host, "v2", u.Name, "blobs", layerDigest)

	var closers []io.Closer

	req, err := http.NewRequest("GET", stringURL, nil)
	if err != nil {
		return closers, err
	}

	of.setBasicAuth(req)

	res, err := of.makeRequest(req, u.Name, schema.MediaTypeRootFS)
	if err != nil {
		return closers, err
	}
	closers = append(closers, res.Body)

	if res.StatusCode != http.StatusOK {
		return closers, fmt.Errorf("unexpected http code: %d, URL: %s", res.StatusCode, req.URL)
	}

	err = os.MkdirAll(blobsDir(outputDir), 0755)
	if err != nil {
		return closers, err
	}

	f, err := os.Create(blobFile(outputDir, layerDigest))
	if err != nil {
		return closers, err
	}
	closers = append(closers, f)

	name := strings.TrimPrefix(layerDigest, "sha256:")
	if len(name) > 12 {
		name = name[:12]
	}

	size, err := strconv.ParseInt(res.Header.Get("content-length"), 10, 64)
	if err != nil {
		size = 0
	}

	cpp.AddCopy(res.Body, name, size, f)

	return closers, nil
}

func writeBlobFromJSON(outputDir, digest string, data interface{}) error {
	jsonblob, err := json.Marshal(data)
	if err != nil {
		return err
	}
	buffer := bytes.NewBuffer(jsonblob)
	_, err = writeBlob(outputDir, digest, buffer)
	if err != nil {
		return err
	}
	return nil
}

func writeBlob(outputDir, digest string, blob io.Reader) (int64, error) {
	err := os.MkdirAll(blobsDir(outputDir), 0755)
	if err != nil {
		return 0, err
	}

	f, err := os.Create(blobFile(outputDir, digest))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return io.Copy(f, blob)
}

func (of *OCIFetcher) makeRequest(req *http.Request, repo string, mediaType string) (*http.Response, error) {
	setBearerHeader := false
	hostAuthTokens, ok := of.hostsV2AuthTokens[req.URL.Host]
	if ok {
		authToken, ok := hostAuthTokens[repo]
		if ok {
			req.Header.Set("Authorization", "Bearer "+authToken)
			setBearerHeader = true
		}
	}

	req.Header.Set("Accept", mediaType)

	of.debugMsg("making request to: %s", req.URL.String())

	client := GetTLSClient(of.insecureSkipTLSVerification)
	res, err := client.Do(req)
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok && of.insecureAllowHTTP && urlErr.Err.Error() == "http: server gave HTTP response to HTTPS client" {
			req.URL.Scheme = "http"
			res, err = client.Do(req)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
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
