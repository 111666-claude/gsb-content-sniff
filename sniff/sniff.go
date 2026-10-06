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
}

// Build 建一个嗅探器。
func Build(patterns []Pattern, policy Policy) *Sniffer {
	return &Sniffer{Patterns: patterns, Policy: policy}
}

// Sniff 返回嗅探到的内容类型。
func (s *Sniffer) Sniff(data []byte, src, declared string, window int, c *Counter) string {
	if declared != "" {
		return declared
	}
	for i := range s.Patterns {
		p := s.Patterns[i]
		ok := len(p.Prefix) > 0
		for j := range p.Prefix {
			c.Scanned++
			if j >= len(data) || data[j] != p.Prefix[j] {
				ok = false
				break
			}
		}
		if ok {
			return p.Type
		}
	}
	return ""
}
