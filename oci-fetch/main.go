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

package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/containers/oci-fetch/lib"
)

var (
	flagDebug                       bool
	flagInsecureAllowHTTP           bool
	flagInsecureSkipTLSVerification bool
	cmdOCIFetch                     = &cobra.Command{
		Use:     "oci-fetch docker://HOST/IMAGENAME[:TAG] FILEPATH",
		Short:   "an OCI image fetcher",
		Long:    "oci-fetch will fetch an OCI image and store it on the local filesystem in a .tar.gz file",
		Example: "oci-fetch docker://registry-1.docker.io/library/nginx:latest nginx.oci",
		Run:     runOCIFetch,
	}
)

func init() {
	cmdOCIFetch.PersistentFlags().BoolVar(&flagDebug, "debug", false, "print out debugging information to stderr")
	cmdOCIFetch.PersistentFlags().BoolVar(&flagInsecureAllowHTTP, "insecure-allow-http", false, "don't enforce encryption when fetching images")
	cmdOCIFetch.PersistentFlags().BoolVar(&flagInsecureSkipTLSVerification, "insecure-skip-tls-verification", false, "don't perform TLS certificate verification")
}

func main() {
	err := cmdOCIFetch.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func runOCIFetch(cmd *cobra.Command, args []string) {
	if len(args) != 2 {
		fmt.Print(cmd.UsageString())
		os.Exit(1)
	}

	outputFilePath := args[1]

	u, err := lib.NewURL(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	tmpDir, err := ioutil.TempDir("", "oci-fetch")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	of := lib.NewOCIFetcher("", "", flagInsecureAllowHTTP, flagInsecureSkipTLSVerification, flagDebug)
	err = of.Fetch(u, tmpDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	f, err := os.Create(outputFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	err = filepath.Walk(tmpDir, newWalkFn(tmpDir, tw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func newWalkFn(parentDir string, tw *tar.Writer) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = strings.TrimPrefix(path, parentDir)
		err = tw.WriteHeader(h)
		if err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(tw, f)
		if err != nil {
			return err
		}
		return nil
	}
}
