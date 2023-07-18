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

package utils

import "github.com/miekg/dns"

const (
	ShortTTL = 1
	LongTTL  = 86400
	Refresh  = 14400
	Retry    = 3600
	Expire   = 604800
)

func DefaultSOARecord(domain string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    LongTTL,
		},
		Refresh: Refresh,
		Retry:   Retry,
		Expire:  Expire,
		Minttl:  LongTTL,
	}
}

func DefaultNSRecord(domain string) *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    LongTTL,
		},
	}
}

func DefaultARecord(domain string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    LongTTL,
		},
	}
}

func DefaultTXTRecord(domain string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    ShortTTL,
		},
	}
}
