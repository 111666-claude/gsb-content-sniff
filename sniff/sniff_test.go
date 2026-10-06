package sniff

import "testing"

func TestBuildStoresPatterns(t *testing.T) {
	s := Build(one(Pattern{Prefix: []byte{1}, Type: "x"}), Policy{})
	if len(s.Patterns) != 1 {
		t.Fatalf("应存下规则：%+v", s.Patterns)
	}
}

func TestPolicyStored(t *testing.T) {
	s := Build(nil, Policy{Trusted: []string{"a"}})
	if len(s.Policy.Trusted) != 1 {
		t.Fatalf("应存下可信名单：%+v", s.Policy)
	}
}

func TestTrustedDeclaredWins(t *testing.T) {
	s := Build(one(Pattern{Prefix: []byte{1}, Type: "image/png"}),
		Policy{Trusted: []string{"t"}, Allowed: map[string]bool{"text/csv": true}})
	got := s.Sniff([]byte{1}, "t", "text/csv", 8, &Counter{})
	if got != "text/csv" {
		t.Fatalf("可信声明应采用，得到 %q", got)
	}
}

func TestExactMatchAtStart(t *testing.T) {
	s := Build(one(Pattern{Prefix: []byte{1, 2}, Type: "x/exact"}), Policy{})
	got := s.Sniff([]byte{1, 2, 3}, "", "", 8, &Counter{})
	if got != "x/exact" {
		t.Fatalf("开头精确匹配应命中，得到 %q", got)
	}
}

func TestDeterministicRepeat(t *testing.T) {
	s := Build(one(Pattern{Prefix: []byte{1, 2}, Type: "x"}), Policy{})
	a := s.Sniff([]byte{1, 2}, "", "", 8, &Counter{})
	b := s.Sniff([]byte{1, 2}, "", "", 8, &Counter{})
	if a != b {
		t.Fatalf("同一输入应稳定：%q vs %q", a, b)
	}
}

func TestCounterCounts(t *testing.T) {
	s := Build(one(Pattern{Prefix: []byte{1}, Type: "x"}), Policy{})
	c := &Counter{}
	s.Sniff([]byte{1}, "", "", 8, c)
	if c.Scanned == 0 {
		t.Fatal("应统计字节比较次数")
	}
}
