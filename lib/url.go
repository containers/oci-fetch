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
	"fmt"
	"strings"
)

const defaultVersion = "latest"

type URL struct {
	Host    string
	Name    string
	Version string
}

func NewURL(url string) *URL {
	tokens := strings.Split(url, "/")
	version := defaultVersion
	if strings.Contains(tokens[len(tokens)-1], ":") {
		lastToken := tokens[len(tokens)-1]
		colonIndex := strings.Index(lastToken, ":")
		version = lastToken[colonIndex+1:]
		tokens[len(tokens)-1] = lastToken[:colonIndex]
	}
	host := tokens[0]
	var name string
	if len(tokens) > 1 {
		name = strings.Join(tokens[1:], "/")
	}
	fmt.Printf("New URL:\n    Host: %s\n    Name: %s\n    Version: %s\n", host, name, version)
	return &URL{
		Host:    host,
		Name:    name,
		Version: version,
	}
}
