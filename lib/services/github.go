/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import (
	"encoding/json"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/utils"
)

// UnmarshalGithubConnector unmarshals the GithubConnector resource from JSON.
func UnmarshalGithubConnector(bytes []byte) (GithubConnector, error) {
	var h ResourceHeader
	if err := json.Unmarshal(bytes, &h); err != nil {
		return nil, trace.Wrap(err)
	}
	switch h.Version {
	case V3:
		var c GithubConnectorV3
		if err := utils.FastUnmarshal(bytes, &c); err != nil {
			return nil, trace.Wrap(err)
		}
		if err := c.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		return &c, nil
	}
	return nil, trace.BadParameter(
		"Github connector resource version %q is not supported", h.Version)
}

// MarshalGithubConnector marshals the GithubConnector resource to JSON.
func MarshalGithubConnector(githubConnector GithubConnector, opts ...MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch githubConnector := githubConnector.(type) {
	case *GithubConnectorV3:
		if version := githubConnector.GetVersion(); version != V3 {
			return nil, trace.BadParameter("mismatched github connector version %v and type %T", version, githubConnector)
		}
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *githubConnector
			copy.SetResourceID(0)
			githubConnector = &copy
		}
		return utils.FastMarshal(githubConnector)
	default:
		return nil, trace.BadParameter("unrecognized github connector version %T", githubConnector)
	}
}
