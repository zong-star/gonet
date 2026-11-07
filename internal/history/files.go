// Package history bounds generated files without traversing subfolders.
package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var localName = regexp.MustCompile(`^(?:scan|topology-export)-([0-9]{8}-[0-9]{6}-[0-9]{3}-[0-9a-f]{6})\.(?:json|log)$`)
var consoleName = regexp.MustCompile(`^scan-ui-([1-9][0-9]*)\.json$`)

type PrunedFiles struct {
	Groups int `json:"groups"`
	Files  int `json:"files"`
}
type fileGroup struct {
	key      string
	names    []string
	modified time.Time
	pinned   bool
}

func groupKey(name string) string {
	if m := localName.FindStringSubmatch(name); m != nil {
		return "local:" + m[1]
	}
	if m := consoleName.FindStringSubmatch(name); m != nil {
		if _, err := strconv.ParseInt(m[1], 10, 64); err != nil {
			return ""
		}
		return "console:" + m[1]
	}
	return ""
}

// PruneOutputs counts a CLI summary/log/raw-export batch as one slot. Unknown
// names, symlinks, directories, latest exports, CSV and images are left alone.
func PruneOutputs(directory string, keep int) (PrunedFiles, error) {
	var out PrunedFiles
	if keep < 2 || keep > 100000 {
		return out, fmt.Errorf("invalid history retention limit")
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return out, err
	}
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return out, fmt.Errorf("history directory must be a real directory")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return out, err
	}
	groups := map[string]*fileGroup{}
	for _, e := range entries {
		key := groupKey(e.Name())
		if key == "" || !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			return out, err
		}
		g := groups[key]
		if g == nil {
			g = &fileGroup{key: key}
			groups[key] = g
		}
		g.names = append(g.names, e.Name())
		if fi.ModTime().After(g.modified) {
			g.modified = fi.ModTime()
		}
	}
	// The current status may point to an older file copied from another machine.
	statusPath := filepath.Join(root, "latest-status.json")
	if fi, e := os.Lstat(statusPath); e == nil && fi.Mode().IsRegular() {
		if b, e := os.ReadFile(statusPath); e == nil {
			var s struct {
				Summary string `json:"summary"`
				Log     string `json:"log"`
				ScanID  int64  `json:"scan_id"`
			}
			if json.Unmarshal(b, &s) == nil {
				for _, p := range []string{s.Summary, s.Log} {
					if p == "" {
						continue
					}
					if !filepath.IsAbs(p) {
						p = filepath.Join(root, p)
					}
					if filepath.Dir(filepath.Clean(p)) != root {
						continue
					}
					if g := groups[groupKey(filepath.Base(p))]; g != nil {
						g.pinned = true
					}
				}
				if g := groups[fmt.Sprintf("console:%d", s.ScanID)]; g != nil {
					g.pinned = true
				}
			}
		}
	}
	ordered := make([]*fileGroup, 0, len(groups))
	for _, g := range groups {
		ordered = append(ordered, g)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].pinned != ordered[j].pinned {
			return ordered[i].pinned
		}
		if !ordered[i].modified.Equal(ordered[j].modified) {
			return ordered[i].modified.After(ordered[j].modified)
		}
		if strings.HasPrefix(ordered[i].key, "console:") && strings.HasPrefix(ordered[j].key, "console:") {
			a, _ := strconv.ParseInt(strings.TrimPrefix(ordered[i].key, "console:"), 10, 64)
			b, _ := strconv.ParseInt(strings.TrimPrefix(ordered[j].key, "console:"), 10, 64)
			return a > b
		}
		return ordered[i].key > ordered[j].key
	})
	for i := keep; i < len(ordered); i++ {
		g := ordered[i]
		if g.pinned {
			continue
		}
		for _, name := range g.names {
			path := filepath.Join(root, name)
			// Exact absolute target verification; single-file deletion, never recurse.
			if filepath.Dir(path) != root {
				return out, fmt.Errorf("invalid history target")
			}
			fi, e := os.Lstat(path)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return out, e
			}
			if !fi.Mode().IsRegular() {
				continue
			}
			if e = os.Remove(path); e != nil && !os.IsNotExist(e) {
				return out, e
			}
			out.Files++
		}
		out.Groups++
	}
	return out, nil
}
