/*
Copyright 2015 Gravitational, Inc.

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

package service

import (
	"path/filepath"
	"testing"

	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	config := MakeDefaultConfig()
	require.NotNil(t, config)

	// all 3 services should be enabled by default
	require.True(t, config.Auth.Enabled)
	require.True(t, config.SSH.Enabled)
	require.True(t, config.Proxy.Enabled)

	localAuthAddr := utils.NetAddr{AddrNetwork: "tcp", Addr: "0.0.0.0:3025"}
	localProxyAddr := utils.NetAddr{AddrNetwork: "tcp", Addr: "0.0.0.0:3023"}

	// data dir, hostname and auth server
	require.Equal(t, config.DataDir, defaults.DataDir)
	if len(config.Hostname) < 2 {
		t.Fatal("default hostname wasn't properly set")
	}

	// crypto settings
	require.Equal(t, config.CipherSuites, utils.DefaultCipherSuites())
	// Unfortunately the below algos don't have exported constants in
	// golang.org/x/crypto/ssh for us to use.
	require.Equal(t, config.Ciphers, []string{
		"aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes128-ctr",
		"aes192-ctr",
		"aes256-ctr",
	})
	require.Equal(t, config.KEXAlgorithms, []string{
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
	})
	require.Equal(t, config.MACAlgorithms, []string{
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-256",
	})
	require.Nil(t, config.CASignatureAlgorithm)

	// auth section
	auth := config.Auth
	require.Equal(t, auth.SSHAddr, localAuthAddr)
	require.Equal(t, auth.Limiter.MaxConnections, int64(defaults.LimiterMaxConnections))
	require.Equal(t, auth.Limiter.MaxNumberOfUsers, defaults.LimiterMaxConcurrentUsers)
	require.Equal(t, config.Auth.StorageConfig.Type, lite.GetName())
	require.Equal(t, auth.StorageConfig.Params[defaults.BackendPath], filepath.Join(config.DataDir, defaults.BackendDir))

	// SSH section
	ssh := config.SSH
	require.Equal(t, ssh.Limiter.MaxConnections, int64(defaults.LimiterMaxConnections))
	require.Equal(t, ssh.Limiter.MaxNumberOfUsers, defaults.LimiterMaxConcurrentUsers)

	// proxy section
	proxy := config.Proxy
	require.Equal(t, proxy.SSHAddr, localProxyAddr)
	require.Equal(t, proxy.Limiter.MaxConnections, int64(defaults.LimiterMaxConnections))
	require.Equal(t, proxy.Limiter.MaxNumberOfUsers, defaults.LimiterMaxConcurrentUsers)
}

// TestAppName makes sure application names are valid subdomains.
func TestAppName(t *testing.T) {
	tests := []struct {
		desc     string
		inName   string
		outValid bool
	}{
		{
			desc:     "valid subdomain",
			inName:   "foo",
			outValid: true,
		},
		{
			desc:     "subdomain cannot start with a dash",
			inName:   "-foo",
			outValid: false,
		},
		{
			desc:     `subdomain cannot contain the exclamation mark character "!"`,
			inName:   "foo!bar",
			outValid: false,
		},
		{
			desc:     "subdomain of length 63 characters is valid (maximum length)",
			inName:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			outValid: true,
		},
		{
			desc:     "subdomain of length 64 characters is invalid",
			inName:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			outValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			a := App{
				Name:       tt.inName,
				URI:        "http://localhost:8080",
				PublicAddr: "foo.example.com",
			}
			err := a.Check()
			if tt.outValid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestCheckDatabase(t *testing.T) {
	tests := []struct {
		desc       string
		inDatabase Database
		outErr     bool
	}{
		{
			desc: "ok",
			inDatabase: Database{
				Name:     "example",
				Protocol: defaults.ProtocolPostgres,
				URI:      "localhost:5432",
			},
			outErr: false,
		},
		{
			desc: "empty database name",
			inDatabase: Database{
				Protocol: defaults.ProtocolPostgres,
				URI:      "localhost:5432",
			},
			outErr: true,
		},
		{
			desc: "invalid database name",
			inDatabase: Database{
				Name:     "??--++",
				Protocol: defaults.ProtocolPostgres,
				URI:      "localhost:5432",
			},
			outErr: true,
		},
		{
			desc: "invalid database protocol",
			inDatabase: Database{
				Name:     "example",
				Protocol: "unknown",
				URI:      "localhost:5432",
			},
			outErr: true,
		},
		{
			desc: "invalid database uri",
			inDatabase: Database{
				Name:     "example",
				Protocol: defaults.ProtocolPostgres,
				URI:      "localhost",
			},
			outErr: true,
		},
		{
			desc: "invalid database CA cert",
			inDatabase: Database{
				Name:     "example",
				Protocol: defaults.ProtocolPostgres,
				URI:      "localhost:5432",
				CACert:   []byte("cert"),
			},
			outErr: true,
		},
		{
			desc: "GCP valid configuration",
			inDatabase: Database{
				Name:     "example",
				Protocol: defaults.ProtocolPostgres,
				URI:      "localhost:5432",
				GCP: DatabaseGCP{
					ProjectID:  "project-1",
					InstanceID: "instance-1",
				},
				CACert: fixtures.LocalhostCert,
			},
			outErr: false,
		},
		{
			desc: "GCP project ID specified without instance ID",
			inDatabase: Database{
				Name:     "example",
				Protocol: defaults.ProtocolPostgres,
				URI:      "localhost:5432",
				GCP: DatabaseGCP{
					ProjectID: "project-1",
				},
				CACert: fixtures.LocalhostCert,
			},
			outErr: true,
		},
		{
			desc: "GCP instance ID specified without project ID",
			inDatabase: Database{
				Name:     "example",
				Protocol: defaults.ProtocolPostgres,
				URI:      "localhost:5432",
				GCP: DatabaseGCP{
					InstanceID: "instance-1",
				},
				CACert: fixtures.LocalhostCert,
			},
			outErr: true,
		},
		{
			desc: "GCP root cert missing",
			inDatabase: Database{
				Name:     "example",
				Protocol: defaults.ProtocolPostgres,
				URI:      "localhost:5432",
				GCP: DatabaseGCP{
					ProjectID:  "project-1",
					InstanceID: "instance-1",
				},
			},
			outErr: true,
		},
		{
			desc: "GCP unsupported for MySQL",
			inDatabase: Database{
				Name:     "example",
				Protocol: defaults.ProtocolMySQL,
				URI:      "localhost:3306",
				GCP: DatabaseGCP{
					ProjectID:  "project-1",
					InstanceID: "instance-1",
				},
				CACert: fixtures.LocalhostCert,
			},
			outErr: true,
		},
		{
			desc: "Redshift region not set",
			inDatabase: Database{
				Name:     "example",
				Protocol: defaults.ProtocolPostgres,
				URI:      "redshift-cluster-1.aaa.us-east-1.redshift.amazonaws.com:5439",
				AWS: DatabaseAWS{
					Redshift: DatabaseAWSRedshift{
						ClusterID: "redshift-cluster-1",
					},
				},
			},
			outErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			err := test.inDatabase.Check()
			if test.outErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestParseHeaders validates parsing of strings into http header objects.
func TestParseHeaders(t *testing.T) {
	tests := []struct {
		desc string
		in   []string
		out  []Header
		err  string
	}{
		{
			desc: "parse multiple headers",
			in: []string{
				"Host: example.com    ",
				"X-Teleport-Logins: root, {{internal.logins}}",
				"X-Env  : {{external.env}}",
				"X-Env: env:prod",
			},
			out: []Header{
				{Name: "Host", Value: "example.com"},
				{Name: "X-Teleport-Logins", Value: "root, {{internal.logins}}"},
				{Name: "X-Env", Value: "{{external.env}}"},
				{Name: "X-Env", Value: "env:prod"},
			},
		},
		{
			desc: "invalid header format (missing value)",
			in:   []string{"X-Header"},
			err:  `failed to parse "X-Header" as http header`,
		},
		{
			// Empty header value is not valid as per https://tools.ietf.org/html/rfc7230#section-3.2.
			desc: "invalid header format (empty value)",
			in:   []string{"X-Empty:"},
			err:  `http header "X-Empty:" value is empty`,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			out, err := ParseHeaders(test.in)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.out, out)
			}
		})
	}
}
