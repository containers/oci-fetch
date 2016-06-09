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

package schema

import (
	"encoding/json"
	"errors"
)

var (
	ErrIncorrectMediaType = errors.New("incorrect mediaType")
	ErrMissingConfig      = errors.New("the config field is empty")
	ErrMissingLayers      = errors.New("the layers field is empty")
)

type ImageManifest struct {
	SchemaVersion int                    `json:"schemaVersion"`
	MediaType     string                 `json:"mediaType"`
	Config        *ImageManifestDigest   `json:"config"`
	Layers        []*ImageManifestDigest `json:"layers"`
	Annotations   map[string]string      `json:"annotations"`
}

type ImageManifestDigest struct {
	MediaType string `json:"mediaType"`
	Size      int    `json:"size"`
	Digest    string `json:"digest"`
}

func (im *ImageManifest) String() string {
	manblob, err := json.Marshal(im)
	if err != nil {
		return err.Error()
	}
	return string(manblob)
}

func (im *ImageManifest) PrettyString() string {
	manblob, err := json.MarshalIndent(im, "", "    ")
	if err != nil {
		return err.Error()
	}
	return string(manblob)
}

func (im *ImageManifest) Validate() error {
	if im.MediaType != MediaTypeManifest {
		return ErrIncorrectMediaType
	}
	if im.Config == nil {
		return ErrMissingConfig
	}
	if len(im.Layers) == 0 {
		return ErrMissingLayers
	}
	return nil
}
