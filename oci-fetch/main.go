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
	"fmt"
	"os"

	"github.com/opencontainers/oci-fetch/lib"
	"github.com/spf13/cobra"
)

var (
	flagDebug                       bool
	flagInsecureAllowHTTP           bool
	flagInsecureSkipTLSVerification bool
	cmdOCIFetch                     = &cobra.Command{
		Use:     "oci-fetch HOST/IMAGENAME[:TAG]",
		Short:   "an OCI-compliant image fetcher",
		Example: "oci-fetch registry-1.docker.io/library/nginx:latest",
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
	if len(args) != 1 {
		cmd.Usage()
		os.Exit(1)
	}
	u, err := lib.NewURL(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	of := lib.NewOCIFetcher("", "", flagInsecureAllowHTTP, flagInsecureSkipTLSVerification, flagDebug)
	err = of.Fetch(u, "output")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
