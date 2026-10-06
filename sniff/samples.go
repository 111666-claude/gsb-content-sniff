package sniff

import "fmt"

// Scenario 是一个固定场景，用来复现题面里的锚点。
type Scenario struct {
	Name string
	Run  func() map[string]any
}

func one(p Pattern) []Pattern { return []Pattern{p} }

// Samples 返回全部场景。
func Samples() []Scenario {
	return []Scenario{
		{Name: "mask", Run: func() map[string]any {
			s := Build(one(Pattern{
				Tag: "png", Prefix: []byte{0x89, 0x50, 0x4E, 0x47},
				Mask: []byte{0xFF, 0xFF, 0x00, 0x00}, Type: "image/png", Priority: 10,
			}), Policy{})
			return map[string]any{"type": s.Sniff([]byte{0x89, 0x50, 0xAA, 0xBB}, "", "", 8, &Counter{})}
		}},
		{Name: "wildfirst", Run: func() map[string]any {
			s := Build(one(Pattern{
				Tag: "png", Prefix: []byte{0x00, 0x41},
				Mask: []byte{0x00, 0xFF}, Type: "image/png", Priority: 5,
			}), Policy{})
			return map[string]any{"type": s.Sniff([]byte{0x99, 0x41}, "", "", 8, &Counter{})}
		}},
		{Name: "window", Run: func() map[string]any {
			s := Build(one(Pattern{Tag: "long", Prefix: []byte{1, 2, 3, 4}, Type: "x/long", Priority: 10}), Policy{})
			return map[string]any{"type": s.Sniff([]byte{1, 2, 3, 4, 5}, "", "", 2, &Counter{})}
		}},
		{Name: "arbitrate", Run: func() map[string]any {
			s := Build([]Pattern{
				{Tag: "generic", Prefix: []byte{1}, Type: "application/octet-stream", Priority: 1},
				{Tag: "specific", Prefix: []byte{1, 2}, Type: "image/x-specific", Priority: 9},
			}, Policy{})
			return map[string]any{"type": s.Sniff([]byte{1, 2}, "", "", 8, &Counter{})}
		}},
		{Name: "declared", Run: func() map[string]any {
			s := Build(one(Pattern{Tag: "png", Prefix: []byte{0x89}, Type: "image/png", Priority: 1}),
				Policy{Trusted: []string{"trusted"}, Allowed: map[string]bool{"text/csv": true}})
			return map[string]any{"type": s.Sniff([]byte{0x89}, "spoof", "text/plain", 8, &Counter{})}
		}},
		{Name: "unknown", Run: func() map[string]any {
			s := Build(one(Pattern{Tag: "png", Prefix: []byte{0x89}, Type: "image/png", Priority: 1}), Policy{})
			return map[string]any{"type": s.Sniff([]byte{0x00, 0x00}, "", "", 8, &Counter{})}
		}},
	}
}

// Work 跑规模线场景。
func Work(n int) map[string]any {
	patterns := make([]Pattern, n)
	for i := range patterns {
		patterns[i] = Pattern{
			Tag:    fmt.Sprintf("p%04d", i),
			Prefix: []byte{byte(i%251 + 1)},
			Type:   fmt.Sprintf("t%04d", i),
		}
	}
	s := Build(patterns, Policy{})
	data := make([]byte, n)
	c := &Counter{}
	for i := 0; i < n; i++ {
		s.Sniff(data, "", "", 4, c)
	}
	return map[string]any{"patterns": n, "scanned": c.Scanned}
}
