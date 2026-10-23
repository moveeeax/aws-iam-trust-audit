package iampolicy

import "sort"

func sortEntries(e []ConditionEntry) {
	sort.Slice(e, func(i, j int) bool {
		if e[i].Key != e[j].Key {
			return e[i].Key < e[j].Key
		}
		return e[i].Operator < e[j].Operator
	})
}
