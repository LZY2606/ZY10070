package sim

import "zonesim/internal/dns"

type resolverAt struct{}

func (resolverAt) answer(z *dns.Zone, q Query, now int64) dns.Answer {
	r := &dns.Resolver{Zone: z, Now: now}
	return r.Resolve(q.Name, q.Type)
}
