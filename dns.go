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

package dns

import (
	"context"
	"errors"
	"fmt"
	"github.com/loopholelabs/dns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"net"
	"strings"
	"sync"
)

var (
	ErrDisabled        = errors.New("dns is disabled")
	ErrInvalidPublicIP = errors.New("invalid public ip")
)

const (
	Mbox = "admin."
)

type Options struct {
	LogName         string
	Disabled        bool
	ListenAddress   string
	PublicIP        string
	RootDomain      string
	CNAMERootDomain string
}

type DNS struct {
	logger  *zerolog.Logger
	options *Options
	storage Storage

	server                *dns.Server
	parsedPublicIP        net.IP
	parsedRootDomain      string
	parsedCNAMERootDomain string

	dnsChallengesMu sync.RWMutex
	dnsChallenges   map[string]string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(options *Options, storage Storage, logger *zerolog.Logger) (*DNS, error) {
	l := logger.With().Str(options.LogName, "DNS").Logger()
	if options.Disabled {
		l.Warn().Msg("disabled")
		return nil, ErrDisabled
	}

	parsedPublicIP := net.ParseIP(options.PublicIP)
	if parsedPublicIP == nil {
		return nil, ErrInvalidPublicIP
	}

	parsedRootDomain := dns.Fqdn(strings.ToLower(options.RootDomain))
	parsedCNAMERootDomain := dns.Fqdn(strings.ToLower(options.CNAMERootDomain))

	return &DNS{
		logger:                &l,
		options:               options,
		storage:               storage,
		parsedPublicIP:        parsedPublicIP,
		parsedRootDomain:      parsedRootDomain,
		parsedCNAMERootDomain: parsedCNAMERootDomain,
		dnsChallenges:         make(map[string]string),
	}, nil
}

func (d *DNS) Start() error {
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.dnsChallengesMu.Lock()
	dnsChallengeEvents := d.storage.SubscribeToDNSChallenges(d.ctx)
	d.wg.Add(1)
	go d.subscribeToChallengeEvents(dnsChallengeEvents)
	d.logger.Info().Msg("subscribed to dns challenges events")
	dnsChallenges, err := d.storage.ListDNSChallenges(d.ctx)
	if err != nil {
		d.dnsChallengesMu.Unlock()
		return fmt.Errorf("failed to list dns challenges: %w", err)
	}
	for _, dnsChallenge := range dnsChallenges {
		d.dnsChallenges[dnsChallenge.ID] = dnsChallenge.Challenge
	}
	d.dnsChallengesMu.Unlock()

	d.logger.Debug().Msgf("starting dns on %s", d.options.ListenAddress)
	d.server = &dns.Server{
		Addr:    d.options.ListenAddress,
		Net:     "udp",
		Handler: dns.HandlerFunc(d.handle),
	}

	return d.server.ListenAndServe()
}

func (d *DNS) Stop() error {
	if d.cancel != nil {
		d.cancel()
	}

	if d.server != nil {
		err := d.server.Shutdown()
		if err != nil {
			return err
		}
	}

	d.wg.Wait()
	return nil
}

func (d *DNS) ValidTXTRecordQuestion(domain string) (bool, string) {
	if qualifiers := strings.SplitN(domain, ".", 2); len(qualifiers) == 2 && qualifiers[1] == d.parsedRootDomain {
		return true, qualifiers[0]
	}
	return false, ""
}

func (d *DNS) ValidARecordQuestion(domain string) bool {
	if len(domain) >= len(d.parsedRootDomain) && domain[len(domain)-len(d.parsedRootDomain):] == d.parsedRootDomain {
		return true
	}
	return false
}

func (d *DNS) ValidNSRecordQuestion(domain string) bool {
	if len(domain) >= len(d.parsedRootDomain) && domain[len(domain)-len(d.parsedRootDomain):] == d.parsedRootDomain {
		return true
	}
	return false
}

func (d *DNS) ValidSOARecordQuestion(domain string) bool {
	if len(domain) >= len(d.parsedRootDomain) && domain[len(domain)-len(d.parsedRootDomain):] == d.parsedRootDomain {
		return true
	}
	return false
}

func (d *DNS) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.RecursionAvailable = false
	m.Rcode = dns.RcodeNameError

	switch r.Opcode {
	case dns.OpcodeQuery:
		m.Authoritative = true
		d.logger.Debug().Msgf("received query (ID %d) with questions %+v", r.Id, r.Question)
		for _, question := range r.Question {
			question.Name = strings.ToLower(question.Name)
			switch question.Qtype {
			case dns.TypeA:
				if d.ValidARecordQuestion(question.Name) {
					aRecord := utils.DefaultARecord(question.Name)
					aRecord.A = d.parsedPublicIP
					d.logger.Debug().Msgf("received A query for valid domain '%s' (ID %d), responding with A '%s'", question.Name, r.Id, d.options.PublicIP)
					m.Answer = append(m.Answer, aRecord)
				} else {
					d.logger.Warn().Msgf("received A query for invalid domain '%s' (ID %d)", question.Name, r.Id)
				}
			case dns.TypeTXT:
				if ok, identifier := d.ValidTXTRecordQuestion(question.Name); ok {
					d.dnsChallengesMu.RLock()
					challenge, ok := d.dnsChallenges[identifier]
					d.dnsChallengesMu.RUnlock()
					if ok {
						txtRecord := utils.DefaultTXTRecord(question.Name)
						txtRecord.Txt = []string{challenge}
						d.logger.Debug().Msgf("received TXT query for valid identifier '%s' (ID %d), responding with '%s'", identifier, r.Id, challenge)
						m.Answer = append(m.Answer, txtRecord)
					} else {
						d.logger.Warn().Msgf("received TXT query for unknown identifier '%s' (ID %d)", identifier, r.Id)
					}
				} else {
					d.logger.Warn().Msgf("received invalid TXT query '%s' (ID %d)", question.Name, r.Id)
				}
			case dns.TypeNS:
				if d.ValidNSRecordQuestion(question.Name) {
					nsRecord := utils.DefaultNSRecord(question.Name)
					nsRecord.Ns = d.parsedRootDomain
					d.logger.Debug().Msgf("received NS query for valid domain '%s' (ID %d), responding with '%s'", question.Name, r.Id, d.parsedRootDomain)
					m.Answer = append(m.Answer, nsRecord)
				} else {
					d.logger.Warn().Msgf("received NS query for invalid domain '%s' (ID %d)", question.Name, r.Id)
				}
			case dns.TypeSOA:
				if d.ValidSOARecordQuestion(question.Name) {
					soaRecord := utils.DefaultSOARecord(question.Name)
					soaRecord.Ns = d.parsedRootDomain
					soaRecord.Mbox = Mbox + d.parsedRootDomain
					d.logger.Debug().Msgf("received SOA query for valid domain '%s' (ID %d), responding with NS '%s', Serial %d, and Mbox '%s'", question.Name, r.Id, soaRecord.Ns, soaRecord.Serial, soaRecord.Mbox)
					m.Answer = append(m.Answer, soaRecord)
				} else {
					d.logger.Warn().Msgf("received SOA query for invalid domain '%s' (ID %d)", question.Name, r.Id)
				}
			default:
				d.logger.Warn().Msgf("received invalid question type %d (ID %d)", question.Qtype, r.Id)
			}
		}
	default:
		d.logger.Warn().Msgf("received invalid operation %d (ID %d)", r.Opcode, r.Id)
		m.Rcode = dns.RcodeRefused
	}

	if len(m.Answer) > 0 {
		m.Rcode = dns.RcodeSuccess
	}

	err := w.WriteMsg(m)
	if err != nil {
		d.logger.Err(err).Msg("error writing DNS response")
	}
}
