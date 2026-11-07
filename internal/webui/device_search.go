package webui

import (
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"gonet/internal/control"
)

type deviceSearchQuery struct {
	query, vendor, model string
	limit                int
}

type deviceSearchItem struct {
	DeviceID     string  `json:"device_id"`
	Name         string  `json:"name"`
	ManagementIP *string `json:"management_ip"`
	Vendor       string  `json:"vendor"`
	Model        string  `json:"model"`
	MatchType    string  `json:"match_type"`
}

type deviceSearchData struct {
	Items     []deviceSearchItem `json:"items"`
	Total     int                `json:"total"`
	Ambiguous bool               `json:"ambiguous"`
}

func parseDeviceSearch(raw string) (deviceSearchQuery, error) {
	query := deviceSearchQuery{limit: 5}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return query, err
	}
	for key, list := range values {
		if len(list) != 1 || !utf8.ValidString(list[0]) || strings.TrimSpace(list[0]) == "" {
			return query, errors.New("duplicate, invalid or empty parameter")
		}
		value := strings.TrimSpace(list[0])
		switch key {
		case "query":
			query.query = value
		case "vendor":
			query.vendor = value
		case "model":
			query.model = value
		case "limit":
			query.limit, err = parseAPILimit(list[0], 5)
			if err != nil {
				return query, err
			}
		default:
			return query, errors.New("unknown parameter")
		}
	}
	if query.query == "" {
		return query, errors.New("missing query")
	}
	return query, nil
}

func parseAPILimit(raw string, max int) (int, error) {
	n, err := parseDeviceID(raw, nil)
	if err != nil || n > int64(max) {
		return 0, errors.New("invalid limit")
	}
	return int(n), nil
}

func managementIP(addresses []string) *string {
	var first netip.Addr
	for _, raw := range addresses {
		if addr, err := netip.ParseAddr(raw); err == nil && addr.Zone() == "" {
			addr = addr.Unmap()
			if !first.IsValid() || addr.Compare(first) < 0 {
				first = addr
			}
		}
	}
	if !first.IsValid() {
		return nil
	}
	value := first.String()
	return &value
}

func findDevices(devices []control.Device, query deviceSearchQuery) deviceSearchData {
	type match struct {
		id   int64
		rank int
		item deviceSearchItem
	}
	matches := []match{}
	ip, _ := netip.ParseAddr(query.query)
	ip = ip.Unmap()
	text := strings.ToLower(query.query)
	for _, device := range devices {
		if (query.vendor != "" && !strings.EqualFold(query.vendor, device.Vendor)) ||
			(query.model != "" && !strings.EqualFold(query.model, device.Model)) {
			continue
		}
		item := deviceSearchItem{DeviceID: idString(device.ID), Name: device.Name, Vendor: device.Vendor, Model: device.Model}
		rank := 0
		if ip.IsValid() {
			for _, raw := range device.AccessAddresses {
				if addr, err := netip.ParseAddr(raw); err == nil && addr.Unmap() == ip {
					value := ip.String()
					item.ManagementIP, item.MatchType = &value, "management_ip"
					rank = 1
					break
				}
			}
		} else {
			nameRank := deviceTextMatch(strings.ToLower(device.Name), text)
			sysRank := deviceTextMatch(strings.ToLower(device.SysName), text)
			rank, item.MatchType = nameRank, "name"
			if sysRank > nameRank {
				rank, item.MatchType = sysRank, "sys_name"
			}
			if rank > 0 {
				item.ManagementIP = managementIP(device.AccessAddresses)
			}
		}
		if rank > 0 {
			matches = append(matches, match{id: device.ID, rank: rank, item: item})
		}
	}
	slices.SortFunc(matches, func(a, b match) int {
		if a.rank != b.rank {
			return b.rank - a.rank
		}
		return compareID(a.id, b.id)
	})
	result := deviceSearchData{Items: []deviceSearchItem{}, Total: len(matches), Ambiguous: len(matches) > 1 && matches[0].rank == matches[1].rank}
	for _, hit := range matches[:min(query.limit, len(matches))] {
		result.Items = append(result.Items, hit.item)
	}
	return result
}

func deviceTextMatch(value, query string) int {
	switch {
	case value == query:
		return 3
	case strings.HasPrefix(value, query):
		return 2
	case strings.Contains(value, query):
		return 1
	default:
		return 0
	}
}
