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

package client

import (
	"github.com/loopholelabs/dns"
	dnsClient "github.com/miekg/dns"
	"github.com/rs/zerolog"
	"time"
)

var (
	nameservers = []string{
		"1.1.1.1:53",
		"1.0.0.1:53",
		"8.8.8.8:53",
		"8.8.4.4:53",
	}
)

type Client struct {
	logger  *zerolog.Logger
	options *dns.Options

	client *dnsClient.Client
}

func New(options *dns.Options, logger *zerolog.Logger) (*Client, error) {
	l := logger.With().Str(options.LogName, "DNS").Logger()
	if options.Disabled {
		l.Warn().Msg("disabled")
		return nil, dns.ErrDisabled
	}

	return &Client{
		logger:  &l,
		options: options,
		client: &dnsClient.Client{
			Timeout: time.Second * 5,
		},
	}, nil
}

func (c *Client) LookupCNAME(domain string) ([]string, error) {
	dnsRequest := new(dnsClient.Msg)
	dnsRequest.SetQuestion(FQDN(domain), dnsClient.TypeCNAME)
	dnsRequest.RecursionDesired = true
	dnsRequest.SetEdns0(4096, true)
	var cnames []string
	for _, nameserver := range nameservers {
		resp, _, err := c.client.Exchange(dnsRequest, nameserver)
		if err != nil {
			c.logger.Error().Err(err).Msgf("failed to dial dns for domain %s", domain)
			continue
		}

		if resp.Rcode != dnsClient.RcodeSuccess {
			c.logger.Debug().Msgf("failed to validate dns for domain %s", domain)
			continue
		}

		for _, answer := range resp.Answer {
			if answer.Header().Rrtype == dnsClient.TypeCNAME {
				if cname, ok := answer.(*dnsClient.CNAME); ok {
					cnames = append(cnames, cname.Target)
				}
			}
		}
	}

	return cnames, nil
}

func (c *Client) LookupTXT(domain string) ([]string, error) {
	dnsRequest := new(dnsClient.Msg)
	dnsRequest.SetQuestion(FQDN(domain), dnsClient.TypeTXT)
	dnsRequest.RecursionDesired = true
	dnsRequest.SetEdns0(4096, true)
	var txts []string
	for _, nameserver := range nameservers {
		resp, _, err := c.client.Exchange(dnsRequest, nameserver)
		if err != nil {
			c.logger.Error().Err(err).Msgf("failed to dial dns for domain %s", domain)
			continue
		}

		if resp.Rcode != dnsClient.RcodeSuccess {
			c.logger.Debug().Msgf("failed to validate dns for domain %s", domain)
			continue
		}

		for _, answer := range resp.Answer {
			if answer.Header().Rrtype == dnsClient.TypeTXT {
				if txt, ok := answer.(*dnsClient.TXT); ok {
					txts = append(txts, txt.Txt...)
				}
			}
		}
	}

	return txts, nil
}

func (c *Client) RootDomain() string {
	return c.options.RootDomain
}

func (c *Client) PublicIP() string {
	return c.options.PublicIP
}

func FQDN(domain string) string {
	return dnsClient.Fqdn(domain)
}
