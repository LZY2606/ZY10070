package service

import "zonesim/internal/dns"

type dnsFinding = dns.Finding

func dnsValidate(a, b *dns.Zone) []dns.Finding { return dns.ValidateCandidate(a, b) }

func splitRRKey(k string) (string, string) {
	for i := len(k) - 1; i >= 0; i-- {
		if k[i] == ' ' {
			return k[:i], k[i+1:]
		}
	}
	return k, ""
}
