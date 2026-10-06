// Package sniff 按魔术字节嗅探内容类型。
package sniff

// Counter 记录字节比较次数。
type Counter struct {
	Scanned int
}

// Pattern 是一条魔术规则。
type Pattern struct {
	Tag      string
	Prefix   []byte
	Mask     []byte
	Type     string
	Priority int
}

// Policy 是可信来源名单与允许被声明的类型。
type Policy struct {
	Trusted []string
	Allowed map[string]bool
}

// Fallback 是表里没有命中时的兜底类型。
const Fallback = "application/octet-stream"

// Sniffer 是嗅探器。
type Sniffer struct {
	Patterns []Pattern
	Policy   Policy

	byFirst  map[byte][]int
	wildcard []int
	trusted  map[string]bool
}

// Build 建一个嗅探器。
func Build(patterns []Pattern, policy Policy) *Sniffer {
	s := &Sniffer{
		Patterns: patterns,
		Policy:   policy,
		byFirst:  map[byte][]int{},
		trusted:  map[string]bool{},
	}
	for _, src := range policy.Trusted {
		s.trusted[src] = true
	}
	for i, p := range patterns {
		if len(p.Prefix) == 0 {
			continue
		}
		if p.Mask != nil && len(p.Mask) > 0 && p.Mask[0] == 0x00 {
			s.wildcard = append(s.wildcard, i)
			continue
		}
		s.byFirst[p.Prefix[0]] = append(s.byFirst[p.Prefix[0]], i)
	}
	return s
}

// exactBits 返回规则里掩码为 0xFF 的位数；掩码为 nil 时逐字节比较。
func exactBits(p Pattern) int {
	if p.Mask == nil {
		return len(p.Prefix)
	}
	n := 0
	for _, m := range p.Mask {
		if m == 0xFF {
			n++
		}
	}
	return n
}

// match 判断规则是否命中数据窗口，c 统计字节比较次数。
func match(p Pattern, data []byte, c *Counter) bool {
	for j := range p.Prefix {
		if p.Mask != nil && j < len(p.Mask) && p.Mask[j] == 0x00 {
			continue
		}
		c.Scanned++
		if j >= len(data) || data[j] != p.Prefix[j] {
			return false
		}
	}
	return true
}

// better 按优先级、前缀长度、精确位数、类型名升序仲裁。
func better(a, b Pattern) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if len(a.Prefix) != len(b.Prefix) {
		return len(a.Prefix) > len(b.Prefix)
	}
	if ea, eb := exactBits(a), exactBits(b); ea != eb {
		return ea > eb
	}
	return a.Type < b.Type
}

// Sniff 返回嗅探到的内容类型。
func (s *Sniffer) Sniff(data []byte, src, declared string, window int, c *Counter) string {
	if declared != "" && s.trusted[src] && s.Policy.Allowed[declared] {
		return declared
	}
	if window > len(data) {
		window = len(data)
	}
	view := data[:window]

	var anchored []int
	if len(view) > 0 {
		anchored = s.byFirst[view[0]]
	}
	candidates := make([]int, 0, len(anchored)+len(s.wildcard))
	candidates = append(candidates, anchored...)
	candidates = append(candidates, s.wildcard...)

	best := -1
	for _, i := range candidates {
		p := s.Patterns[i]
		if len(p.Prefix) == 0 || len(p.Prefix) > window {
			continue
		}
		if !match(p, view, c) {
			continue
		}
		if best < 0 || better(p, s.Patterns[best]) {
			best = i
		}
	}
	if best < 0 {
		return Fallback
	}
	return s.Patterns[best].Type
}
