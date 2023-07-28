/*
	Copyright 2023 Loophole Labs

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

package config

import (
	"errors"
	"github.com/loopholelabs/dns"
	"github.com/spf13/pflag"
)

var (
	ErrListenAddressRequired   = errors.New("listen address is required")
	ErrPublicIPRequired        = errors.New("public ip is required")
	ErrRootDomainRequired      = errors.New("root domain is required")
	ErrCNAMERootDomainRequired = errors.New("cname root domain is required")
)

const (
	DefaultDisabled = false
)

type Config struct {
	Disabled        bool   `mapstructure:"disabled"`
	ListenAddress   string `mapstructure:"listen_address"`
	PublicIP        string `mapstructure:"public_ip"`
	RootDomain      string `mapstructure:"root_domain"`
	CNAMERootDomain string `mapstructure:"cname_root_domain"`
}

func New() *Config {
	return &Config{
		Disabled: DefaultDisabled,
	}
}

func (c *Config) Validate() error {
	if !c.Disabled {
		if c.ListenAddress == "" {
			return ErrListenAddressRequired
		}

		if c.PublicIP == "" {
			return ErrPublicIPRequired
		}

		if c.RootDomain == "" {
			return ErrRootDomainRequired
		}

		if c.CNAMERootDomain == "" {
			return ErrCNAMERootDomainRequired
		}
	}

	return nil
}

func (c *Config) RootPersistentFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&c.Disabled, "dns-disabled", DefaultDisabled, "Disable dns")
	flags.StringVar(&c.ListenAddress, "dns-listen-address", "", "The listen address for the dns service")
	flags.StringVar(&c.PublicIP, "dns-public-ip", "", "The public ip for the dns service")
	flags.StringVar(&c.RootDomain, "dns-root-domain", "", "The root domain for the dns service")
	flags.StringVar(&c.CNAMERootDomain, "dns-cname-root-domain", "", "The cname root domain for the dns service")
}

func (c *Config) GenerateOptions(logName string) *dns.Options {
	return &dns.Options{
		LogName:         logName,
		Disabled:        c.Disabled,
		ListenAddress:   c.ListenAddress,
		PublicIP:        c.PublicIP,
		RootDomain:      c.RootDomain,
		CNAMERootDomain: c.CNAMERootDomain,
	}
}
