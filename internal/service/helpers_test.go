package service

import "zonesim/internal/sim"

func simQuery(name, typ string) []sim.Query {
	return []sim.Query{{QName: name, QType: typ}}
}

func simQ(name, typ string) sim.Query { return sim.Query{QName: name, QType: typ} }
