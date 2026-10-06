# content-sniff

按魔术字节嗅探内容类型：带检查窗口、通配位、多命中仲裁，以及一层可信来源的声明覆盖。只用标准库。

```
go test ./...
go vet ./...
go run ./cmd/sniff --sample=mask
go run ./cmd/sniff --sample=wildfirst
go run ./cmd/sniff --sample=window
go run ./cmd/sniff --sample=arbitrate
go run ./cmd/sniff --sample=declared
go run ./cmd/sniff --sample=unknown
go run ./cmd/sniff --sample=work
```

## 口径

- **检查窗口**：只看数据开头的 `window` 个字节；规则需要的字节数超过窗口就不参与本次判定。
- **通配位**：规则的掩码与前缀等长；掩码为 `nil` 表示逐字节比较，掩码某位为 `0x00` 表示该位不比较，其余位按前缀比较。
- **仲裁**：一条数据可能命中多条规则，取优先级最高的一条；优先级相同取前缀更长的；再相同取精确位（掩码为 `0xFF` 的位）更多的；仍相同取类型名升序最小的。
- **可信声明层**：来源在可信名单里、且声明类型在允许名单里时，直接采用声明；否则忽略声明，走规则表。
- **兜底**：规则表没有命中时返回 `application/octet-stream`。

## 不变量

- 判定结果只取决于数据窗口内的开头字节、来源与声明；同一输入得到同一结果。
- 命中规则的前缀在窗口内对齐，长度不超过窗口。
- `scanned`（字节比较次数）不随规则表大小线性放大：两千条规则上嗅探两千次，`scanned` 不超过 6000。

## 输出契约

场景打印一行 JSON，键为 `type`。`--sample=work` 打印 `{"patterns": N, "scanned": N}`。
