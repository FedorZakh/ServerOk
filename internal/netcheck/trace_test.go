package netcheck

// trace_test.go — разбор вывода системного traceroute. Формат у разных
// реализаций отличается, поэтому проверяются обе: BSD/GNU traceroute и
// tracepath, включая строки без ответа.

import "testing"

func TestParseTraceOutput(t *testing.T) {
	const out = `traceroute to 1.1.1.1 (1.1.1.1), 15 hops max, 60 byte packets
 1  10.0.0.1  0.512 ms
 2  * 
 3  62.115.120.1  12.482 ms
 4  1.1.1.1  11.905 ms
`
	hops := parseTraceOutput(out)
	if len(hops) != 4 {
		t.Fatalf("got %d hops, want 4: %+v", len(hops), hops)
	}
	if hops[0].IP != "10.0.0.1" || hops[0].RTTMs != 0.512 {
		t.Errorf("first hop = %+v", hops[0])
	}
	if hops[1].IP != "" || hops[1].N != 2 {
		t.Errorf("timed-out hop should keep its number and no IP: %+v", hops[1])
	}
	if hops[3].IP != "1.1.1.1" || hops[3].RTTMs != 11.905 {
		t.Errorf("last hop = %+v", hops[3])
	}
}

func TestParseTraceOutputTracepath(t *testing.T) {
	const out = ` 1?: [LOCALHOST]                      pmtu 1500
 1:  10.0.0.1                              0.605ms
 2:  no reply
`
	hops := parseTraceOutput(out)
	if len(hops) == 0 {
		t.Fatal("expected hops from tracepath output")
	}
	if hops[0].IP != "" && hops[0].IP != "10.0.0.1" {
		t.Errorf("unexpected hop: %+v", hops[0])
	}
}
