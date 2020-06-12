package config_test

import (
	"fmt"
	"testing"

	"github.com/Benbentwo/blessclient/pkg/config"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

func TestSSHConfig(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	sshConf := &config.SSHConfig{
		Bastions: []config.Bastion{
			config.Bastion{},
		},
	}

	r.Equal("blessclient run", sshConf.Bastions[0].SSHExecCommand.String())

	s, err := sshConf.String()
	r.Nil(err)
	r.Contains(s, "######### Generated by blessclient vundefined+undefined-dirty at")
	r.Contains(s, fmt.Sprint("exec \"blessclient run\""))
}

func TestCustomExecCommand(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	contents := "test custom exec command"
	expected := config.SSHExecCommand(contents)

	sshConf := &config.SSHConfig{
		Bastions: []config.Bastion{
			{
				SSHExecCommand: &expected,
			},
		},
	}

	// Before template
	r.Equal(contents, sshConf.Bastions[0].SSHExecCommand.String())

	// Template
	s, err := sshConf.String()
	r.Nil(err)
	r.Contains(s, "######### Generated by blessclient vundefined+undefined-dirty at")
	r.Contains(s, expected.String())
	r.Contains(s, fmt.Sprintf("exec \"%s\"", contents))
}

func TestUserOverride(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	sshConf := &config.SSHConfig{
		Bastions: []config.Bastion{
			{
				Host: config.Host{
					Pattern: "test0",
					User:    "foo",
				},
				Hosts: []config.Host{
					{
						User:    "bar",
						Pattern: "10.0.0.*",
					},
					{
						// no user override here
						Pattern: "10.0.0.*",
					},
				},
			},
		},
	}

	expected := `
Match OriginalHost  test0 exec "blessclient run"
  User foo

Host test0
  User foo

Host 10.0.0.*
	ProxyJump test0
	User bar

Host 10.0.0.*
	ProxyJump test0
	User foo
`

	config, err := sshConf.String()
	r.NoError(err)
	r.Contains(config, expected)
}

func TestUnmarshalConfig(t *testing.T) {
	// test we can roundtrip a config through yaml
	t.Parallel()
	r := require.New(t)

	sshConf := &config.SSHConfig{
		Bastions: []config.Bastion{
			{
				Host: config.Host{
					Pattern: "test0",
					User:    "foo",
				},
				Hosts: []config.Host{
					{
						User:    "bar",
						Pattern: "10.0.0.*",
					},
					{
						// no user override here
						Pattern: "10.0.0.*",
					},
				},
			},
		},
	}

	data, err := yaml.Marshal(sshConf)
	r.NoError(err)

	newConf := &config.SSHConfig{}
	err = yaml.Unmarshal(data, newConf)
	r.NoError(err)

	r.Equal(sshConf, newConf)
}
