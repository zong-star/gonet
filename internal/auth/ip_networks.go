package auth

import (
	"errors"
	"net/netip"
	"strings"
)

func ParseIPNetworks(addresses []string) ([]netip.Prefix, error) {
	if len(addresses) == 0 || len(addresses) > 64 {
		return nil, errors.New("请填写 1 到 64 个 IP 地址或 CIDR 网段")
	}
	prefixes := make([]netip.Prefix, 0, len(addresses))
	seen := make(map[netip.Prefix]bool)
	for _, value := range addresses {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			addr, addrErr := netip.ParseAddr(value)
			if addrErr != nil || addr.Zone() != "" {
				return nil, errors.New("白名单中有无效的 IP 地址或 CIDR 网段")
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, errors.New("IPv4 映射 IPv6 网段的前缀长度必须至少为 96")
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefix = prefix.Masked()
		if !seen[prefix] {
			prefixes = append(prefixes, prefix)
			seen[prefix] = true
		}
	}
	return prefixes, nil
}
