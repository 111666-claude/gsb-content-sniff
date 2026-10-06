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

	byFirst   map[byte][]int
	wildFirst []int
	exact     []int
	trusted   map[string]bool
}

// Build 建一个嗅探器。
func Build(patterns []Pattern, policy Policy) *Sniffer {
	s := &Sniffer{
		Patterns: patterns,
		Policy:   policy,
		byFirst:  make(map[byte][]int),
		trusted:  make(map[string]bool, len(policy.Trusted)),
		exact:    make([]int, len(patterns)),
	}
	for _, t := range policy.Trusted {
		s.trusted[t] = true
	}
	for i, p := range patterns {
		s.exact[i] = exactBits(p)
		if len(p.Prefix) == 0 {
			continue
		}
		if p.Mask != nil && len(p.Mask) > 0 && p.Mask[0] == 0x00 {
			s.wildFirst = append(s.wildFirst, i)
			continue
		}
		s.byFirst[p.Prefix[0]] = append(s.byFirst[p.Prefix[0]], i)
	}
	return s
}

// exactBits 统计规则的精确位：掩码为 nil 时全部精确，否则数 0xFF 的位。
func exactBits(p Pattern) int {
	if p.Mask == nil {
		return len(p.Prefix)
	}
	n := 0
	for j := range p.Prefix {
		if j >= len(p.Mask) || p.Mask[j] == 0xFF {
			n++
		}
	}
	return n
}

// masked 判断第 j 位是否被掩码跳过。
func masked(p Pattern, j int) bool {
	return p.Mask != nil && j < len(p.Mask) && p.Mask[j] == 0x00
}

// matches 判断规则是否命中数据窗口内的开头字节。
func (s *Sniffer) matches(p Pattern, data []byte, window int, c *Counter) bool {
	n := len(p.Prefix)
	if n == 0 || n > window || n > len(data) {
		return false
	}
	for j := 0; j < n; j++ {
		if masked(p, j) {
			continue
		}
		if c != nil {
			c.Scanned++
		}
		if data[j] != p.Prefix[j] {
			return false
		}
	}
	return true
}

// better 按仲裁口径比较两条命中规则：优先级、前缀长度、精确位数、类型名升序。
func (s *Sniffer) better(a, b int) bool {
	pa, pb := s.Patterns[a], s.Patterns[b]
	if pa.Priority != pb.Priority {
		return pa.Priority > pb.Priority
	}
	if len(pa.Prefix) != len(pb.Prefix) {
		return len(pa.Prefix) > len(pb.Prefix)
	}
	if s.exact[a] != s.exact[b] {
		return s.exact[a] > s.exact[b]
	}
	return pa.Type < pb.Type
}

// Sniff 返回嗅探到的内容类型。
func (s *Sniffer) Sniff(data []byte, src, declared string, window int, c *Counter) string {
	if declared != "" && s.trusted[src] && s.Policy.Allowed[declared] {
		return declared
	}
	best := -1
	try := func(i int) {
		if !s.matches(s.Patterns[i], data, window, c) {
			return
		}
		if best < 0 || s.better(i, best) {
			best = i
		}
	}
	if window > 0 && len(data) > 0 {
		for _, i := range s.byFirst[data[0]] {
			try(i)
		}
	}
	for _, i := range s.wildFirst {
		try(i)
	}
	if best < 0 {
		return Fallback
	}
	return s.Patterns[best].Type
}
