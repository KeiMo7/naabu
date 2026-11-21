package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// Change categories. Each current-round open port ends in exactly one of the
// per-port categories; together with the host-level groups they partition the
// current round's full open-port inventory.
const (
	// CategoryNew: port confirmed open this round on a host that existed last
	// round and whose probe key was scanned in both rounds.
	CategoryNew = "new"
	// CategoryClosed: open last round on a covered host, and the current round
	// actually probed that key and did not find it open.
	CategoryClosed = "closed"
	// CategoryUnchanged: open in both rounds with the same fingerprint.
	CategoryUnchanged = "unchanged"
	// CategoryFingerprintChanged: open in both rounds, service fields differ.
	CategoryFingerprintChanged = "fingerprint_changed"
	// CategoryUncertainResolved: last round the host was incomplete (unknown)
	// or unreachable, so the port was never proven closed; it is a resolved
	// uncertainty, not a new port.
	CategoryUncertainResolved = "uncertain_resolved"
	// CategoryUncertainDropped: open last round on a host that was not fully
	// covered, and not seen this round. Its absence is not a confirmed close.
	CategoryUncertainDropped = "uncertain_dropped"
	// CategoryHostDown: open last round on a host that is now unreachable. It
	// is carried by the host-level group and never counted as "closed".
	CategoryHostDown = "host_down"
)

// Host-level groups.
const (
	// GroupNewTarget: host absent from the previous target set entirely.
	GroupNewTarget = "new_target"
	// GroupHostUnreachable: reachable (or present) last round, unreachable now.
	GroupHostUnreachable = "host_unreachable"
	// GroupHostRecovered: unreachable last round, reachable now. Its ports are
	// reported as a recovery, not as individual new ports.
	GroupHostRecovered = "host_recovered"
	// GroupHostChanged: present in both rounds and currently reachable (or
	// partially covered); ports are compared per entry.
	GroupHostChanged = "host_changed"
)

// PortChange is one entry in a host-level group.
type PortChange struct {
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	Protocol      string     `json:"protocol"`
	Category      string     `json:"category"`
	Current       *PortEntry `json:"current,omitempty"`
	Previous      *PortEntry `json:"previous,omitempty"`
	ChangedFields []string   `json:"changed_fields,omitempty"`
}

// HostGroup collects every change for one host under one host-level reason.
type HostGroup struct {
	Host    string       `json:"host"`
	Group   string       `json:"group"`
	Changes []PortChange `json:"changes"`
}

// Report is the deterministic result of comparing two snapshots.
type Report struct {
	FormatVersion int `json:"format_version"`
	// ScopeMismatch is set when the two rounds probed different port sets.
	ScopeMismatch bool `json:"scope_mismatch"`
	// ScopeWarning explains the mismatch in human terms; empty when scopes match.
	ScopeWarning string `json:"scope_warning,omitempty"`
	// PreviousOnlyScope lists probed keys present only in the previous round.
	PreviousOnlyScope []string `json:"previous_only_scope,omitempty"`
	// CurrentOnlyScope lists probed keys present only in the current round.
	CurrentOnlyScope []string `json:"current_only_scope,omitempty"`

	NewTargets      []HostGroup `json:"new_targets,omitempty"`
	HostUnreachable []HostGroup `json:"host_unreachable,omitempty"`
	HostRecovered   []HostGroup `json:"host_recovered,omitempty"`
	HostChanged     []HostGroup `json:"host_changed,omitempty"`

	// Summary counts per category across all groups. Zero-valued categories
	// are omitted; encoding/json sorts map keys, keeping the bytes stable.
	Summary map[string]int `json:"summary"`
}

// Compare computes the diff of two snapshots. It is pure: it performs no I/O
// and returns an identical report for the same pair of inputs every time.
//
// Both inputs are canonicalized into sorted, deduplicated collections, and
// every grouping iterates in sorted order. Snapshots only ever store open
// ports (never the closed universe), so the work is proportional to the open
// entries plus hosts with explicit state, not to hosts x ports; 100k+ entry
// snapshots are decoded and compared in a single streaming pass over the
// canonical slices.
func Compare(previous, current *Snapshot) (*Report, error) {
	if previous == nil {
		return nil, fmt.Errorf("previous snapshot is nil")
	}
	if current == nil {
		return nil, fmt.Errorf("current snapshot is nil")
	}
	if err := previous.validate(); err != nil {
		return nil, fmt.Errorf("invalid previous snapshot: %w", err)
	}
	if err := current.validate(); err != nil {
		return nil, fmt.Errorf("invalid current snapshot: %w", err)
	}
	previous = previous.canonicalCopy()
	current = current.canonicalCopy()

	report := &Report{
		FormatVersion: FormatVersion,
		Summary:       map[string]int{},
	}

	report.ScopeMismatch, report.PreviousOnlyScope, report.CurrentOnlyScope = scopeDiff(previous.PortScope, current.PortScope)
	if report.ScopeMismatch {
		report.ScopeWarning = fmt.Sprintf(
			"port scope differs between rounds: %d probe key(s) only in the previous round, %d only in the current round; ports outside the shared scope are not classified as closed",
			len(report.PreviousOnlyScope), len(report.CurrentOnlyScope))
	}

	prevHosts := indexHosts(previous.Hosts)
	curHosts := indexHosts(current.Hosts)
	prevPorts := indexPorts(previous.Ports)
	curPorts := indexPorts(current.Ports)
	prevCoverage := newCoverage(previous.Targets, previous.Excluded)
	curCoverage := newCoverage(current.Targets, current.Excluded)
	prevScope := toSet(previous.PortScope)
	curScope := toSet(current.PortScope)
	sharedScope := intersectSets(prevScope, curScope)

	// Deterministic host iteration: the sorted union of every host that has an
	// explicit state or an open port in either round.
	for _, host := range unionHosts([]map[string]string{prevHosts, curHosts}, prevPorts, curPorts) {
		prevStatus, prevKnown := prevHosts[host]
		curStatus, curKnown := curHosts[host]
		prevEntries := prevPorts[host]
		curEntries := curPorts[host]

		// Explicit host state is authoritative: a partially covered host can
		// have some open ports and still leave other ports unprobed, so port
		// evidence must not silently upgrade an "unknown" host to "reachable".
		// Only when the snapshot carries no state at all do open ports imply
		// reachability.
		if !curKnown && len(curEntries) > 0 {
			curStatus, curKnown = HostReachable, true
		}
		if !prevKnown && len(prevEntries) > 0 {
			prevStatus, prevKnown = HostReachable, true
		}

		// A host with no explicit current state may still be covered by the
		// round's planned targets. That distinction is what separates a
		// completed scan with zero open ports from "we did not look".
		curTargeted := false
		if !curKnown && curCoverage.contains(host) {
			curTargeted = true
			if current.Partial {
				curStatus, curKnown = HostUnknown, true
			} else {
				curStatus, curKnown = HostReachable, true
			}
		}

		prevTargeted := prevCoverage.contains(host)
		// A previous round that ended early did not fully cover its target
		// space, so a target with no explicit state may still have unprobed
		// ports. Treat it as uncertain rather than as a covered host with no
		// open ports.
		if !prevKnown && prevTargeted {
			if previous.Partial {
				prevStatus, prevKnown = HostUnknown, true
			} else {
				prevStatus, prevKnown = HostReachable, true
			}
		}

		// A partially completed round cannot vouch for any host's completeness:
		// even a host that answered has probe keys that may never have been
		// tried. Explicit unreachable evidence (host discovery) is still
		// honored because it is a positive finding; open ports keep the host
		// reachable (liveness) but not "covered".
		if previous.Partial && prevStatus == HostReachable {
			prevStatus, prevKnown = HostUnknown, true
		}
		if current.Partial && curStatus == HostReachable {
			curStatus, curKnown = HostUnknown, true
		}
		prevExisting := prevKnown || prevTargeted

		// A host this round never touched (not an explicit target, no explicit
		// state/port observation, outside the coverage set) was simply not
		// scanned. Silence about it is the only honest answer; do not classify
		// it as a new target or as closed ports.
		if !curKnown && !curTargeted {
			continue
		}

		group := HostGroup{Host: host}
		switch {
		// Form 5: expanded target set — isolated, never mixed into existing
		// host diffs.
		case !prevExisting:
			group.Group = GroupNewTarget
			group.Changes = newTargetChanges(host, curEntries, report)
			if len(group.Changes) > 0 {
				report.NewTargets = append(report.NewTargets, group)
			}

		// Form 3: the host itself lost reachability. Carry its previous ports
		// as host_down, not as per-port closures. The group is emitted even
		// with no previous ports: the liveness change is a finding on its own.
		case curStatus == HostUnreachable:
			group.Group = GroupHostUnreachable
			group.Changes = hostDownChanges(host, prevEntries, report)
			report.HostUnreachable = append(report.HostUnreachable, group)

		// Form 6: unreachable last round, reachable now — one recovery group
		// instead of per-port "new". Emitted even with no open ports, because
		// the host coming back is the finding.
		case prevStatus == HostUnreachable:
			group.Group = GroupHostRecovered
			group.Changes = uncertainChanges(host, prevEntries, curEntries, report)
			report.HostRecovered = append(report.HostRecovered, group)

		// Form 2: previous round did not finish this host. Every current port
		// is a resolved uncertainty, never a "new" port; previous ports that
		// are no longer visible are uncertainties, not closures.
		case prevStatus == HostUnknown:
			group.Group = GroupHostChanged
			group.Changes = uncertainChanges(host, prevEntries, curEntries, report)
			if len(group.Changes) > 0 {
				report.HostChanged = append(report.HostChanged, group)
			}

		// Current round did not fully cover the host: same uncertainty rule.
		case curStatus == HostUnknown:
			group.Group = GroupHostChanged
			group.Changes = uncertainChanges(host, prevEntries, curEntries, report)
			if len(group.Changes) > 0 {
				report.HostChanged = append(report.HostChanged, group)
			}

		// Default: a host covered in both rounds — compare ports entry by
		// entry.
		default:
			group.Group = GroupHostChanged
			group.Changes = compareHostPorts(host, prevEntries, curEntries, curScope, sharedScope, report)
			if len(group.Changes) > 0 {
				report.HostChanged = append(report.HostChanged, group)
			}
		}
	}

	report.canonicalize()
	return report, nil
}

// newTargetChanges classifies every port of a newly added target as new. The
// group is separate on purpose: these ports say "the target set grew", not
// "an existing host opened something".
func newTargetChanges(host string, current map[string]PortEntry, report *Report) []PortChange {
	changes := make([]PortChange, 0, len(current))
	for _, entry := range sortedEntries(current) {
		changes = append(changes, PortChange{
			Host: host, Port: entry.Port, Protocol: entry.Protocol,
			Category: CategoryNew, Current: ptrEntry(entry),
		})
		report.Summary[CategoryNew]++
	}
	return changes
}

// hostDownChanges carries the previous open ports of an unreachable host.
func hostDownChanges(host string, previous map[string]PortEntry, report *Report) []PortChange {
	changes := make([]PortChange, 0, len(previous))
	for _, entry := range sortedEntries(previous) {
		changes = append(changes, PortChange{
			Host: host, Port: entry.Port, Protocol: entry.Protocol,
			Category: CategoryHostDown, Previous: ptrEntry(entry),
		})
		report.Summary[CategoryHostDown]++
	}
	return changes
}

// uncertainChanges reports the ports of a host that was incomplete in one of
// the rounds. Current ports are resolved uncertainties; previous ports absent
// now are dropped uncertainties. Neither may be reported as new or closed.
func uncertainChanges(host string, previous, current map[string]PortEntry, report *Report) []PortChange {
	changes := make([]PortChange, 0, len(previous)+len(current))
	for _, entry := range sortedEntries(current) {
		changes = append(changes, PortChange{
			Host: host, Port: entry.Port, Protocol: entry.Protocol,
			Category: CategoryUncertainResolved, Current: ptrEntry(entry),
		})
		report.Summary[CategoryUncertainResolved]++
	}
	for _, entry := range sortedEntries(previous) {
		if _, stillOpen := current[ScopeKey(entry.Protocol, entry.Port)]; stillOpen {
			continue
		}
		changes = append(changes, PortChange{
			Host: host, Port: entry.Port, Protocol: entry.Protocol,
			Category: CategoryUncertainDropped, Previous: ptrEntry(entry),
		})
		report.Summary[CategoryUncertainDropped]++
	}
	return changes
}

// compareHostPorts produces the per-port partition for one host covered in
// both rounds. Every current open port is classified exactly once; previous
// ports are only called closed when the current round actually probed them.
func compareHostPorts(host string, previous, current map[string]PortEntry, curScope, sharedScope map[string]struct{}, report *Report) []PortChange {
	changes := make([]PortChange, 0, len(previous)+len(current))

	// Current open ports: new / unchanged / fingerprint changed. Every current
	// open port inside the shared probe scope lands in exactly one of these,
	// so the three together always equal this round's compared inventory.
	for _, cur := range sortedEntries(current) {
		key := ScopeKey(cur.Protocol, cur.Port)
		prev, existed := previous[key]
		if !existed {
			if _, probedBefore := sharedScope[key]; !probedBefore {
				// The previous round never looked at this key (widened range
				// or explicit ip:port target). Ports outside the shared scope
				// are reported through current_only_scope, never as new: a
				// port nobody probed last round cannot be said to have opened.
				continue
			}
			changes = append(changes, PortChange{
				Host: host, Port: cur.Port, Protocol: cur.Protocol,
				Category: CategoryNew, Current: ptrEntry(cur),
			})
			report.Summary[CategoryNew]++
			continue
		}
		if fields := fingerprintDiff(prev, cur); len(fields) > 0 {
			changes = append(changes, PortChange{
				Host: host, Port: cur.Port, Protocol: cur.Protocol,
				Category: CategoryFingerprintChanged, Current: ptrEntry(cur),
				Previous: ptrEntry(prev), ChangedFields: fields,
			})
			report.Summary[CategoryFingerprintChanged]++
			continue
		}
		changes = append(changes, PortChange{
			Host: host, Port: cur.Port, Protocol: cur.Protocol,
			Category: CategoryUnchanged, Current: ptrEntry(cur), Previous: ptrEntry(prev),
		})
		report.Summary[CategoryUnchanged]++
	}

	// Previously open ports missing now: closed only when the current round
	// probed that key. A narrowed scope must never read as closure.
	for _, prev := range sortedEntries(previous) {
		key := ScopeKey(prev.Protocol, prev.Port)
		if _, stillOpen := current[key]; stillOpen {
			continue
		}
		if _, probedNow := curScope[key]; !probedNow {
			continue
		}
		changes = append(changes, PortChange{
			Host: host, Port: prev.Port, Protocol: prev.Protocol,
			Category: CategoryClosed, Previous: ptrEntry(prev),
		})
		report.Summary[CategoryClosed]++
	}

	sortChanges(changes)
	return changes
}

// fingerprintDiff returns the service fields that differ between two open
// observations of the same port. TLS is a connection-level fact and is
// compared too. An empty slice means the fingerprints are identical.
func fingerprintDiff(previous, current PortEntry) []string {
	changed := make([]string, 0)
	if previous.TLS != current.TLS {
		changed = append(changed, "tls")
	}
	ps, cs := previous.Service, current.Service
	if ps == nil && cs == nil {
		return changed
	}
	if ps == nil || cs == nil {
		return append(changed, "service")
	}
	pairs := []struct {
		field string
		a, b  string
	}{
		{"name", ps.Name, cs.Name},
		{"product", ps.Product, cs.Product},
		{"version", ps.Version, cs.Version},
		{"service_fp", ps.ServiceFP, cs.ServiceFP},
		{"banner", ps.Banner, cs.Banner},
		{"tunnel", ps.Tunnel, cs.Tunnel},
		{"method", ps.Method, cs.Method},
		{"hostname", ps.Hostname, cs.Hostname},
		{"os_type", ps.OSType, cs.OSType},
		{"device_type", ps.DeviceType, cs.DeviceType},
		{"extra_info", ps.ExtraInfo, cs.ExtraInfo},
		{"high_version", ps.HighVersion, cs.HighVersion},
		{"low_version", ps.LowVersion, cs.LowVersion},
		{"proto", ps.Proto, cs.Proto},
		{"rpc_num", ps.RPCNum, cs.RPCNum},
	}
	for _, pair := range pairs {
		if pair.a != pair.b {
			changed = append(changed, pair.field)
		}
	}
	if ps.Confidence != cs.Confidence {
		changed = append(changed, "confidence")
	}
	if !equalSorted(ps.CPEs, cs.CPEs) {
		changed = append(changed, "cpes")
	}
	return changed
}

// WriteReport writes the report atomically as pretty JSON so an interrupted
// comparison never leaves a partial file behind.
func WriteReport(path string, report *Report) error {
	if path == "" {
		return fmt.Errorf("report path is empty")
	}
	data, err := report.MarshalCanonical()
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0600)
}

// MarshalCanonical returns the canonical pretty JSON form of the report
// without mutating the report.
func (r *Report) MarshalCanonical() ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("cannot encode a nil report")
	}
	cp := r.canonicalCopy()
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode report: %w", err)
	}
	return append(data, '\n'), nil
}

// EncodeReport writes the canonical JSON form to a writer (used for stdout).
func EncodeReport(writer io.Writer, report *Report) error {
	data, err := report.MarshalCanonical()
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

// canonicalCopy returns a sorted, deduplicated copy of the report. Summary
// values are copied as-is; every slice is ordered.
func (r *Report) canonicalCopy() *Report {
	if r == nil {
		return nil
	}
	out := &Report{
		FormatVersion:     r.FormatVersion,
		ScopeMismatch:     r.ScopeMismatch,
		ScopeWarning:      r.ScopeWarning,
		PreviousOnlyScope: append([]string(nil), r.PreviousOnlyScope...),
		CurrentOnlyScope:  append([]string(nil), r.CurrentOnlyScope...),
		NewTargets:        copyGroups(r.NewTargets),
		HostUnreachable:   copyGroups(r.HostUnreachable),
		HostRecovered:     copyGroups(r.HostRecovered),
		HostChanged:       copyGroups(r.HostChanged),
		Summary:           make(map[string]int, len(r.Summary)),
	}
	for category, count := range r.Summary {
		out.Summary[category] = count
	}
	out.canonicalize()
	return out
}

func (r *Report) canonicalize() {
	sort.Strings(r.PreviousOnlyScope)
	sort.Strings(r.CurrentOnlyScope)
	sortGroups(r.NewTargets)
	sortGroups(r.HostUnreachable)
	sortGroups(r.HostRecovered)
	sortGroups(r.HostChanged)
	if r.Summary == nil {
		r.Summary = map[string]int{}
	}
}

func copyGroups(groups []HostGroup) []HostGroup {
	out := make([]HostGroup, len(groups))
	for i, group := range groups {
		out[i] = HostGroup{
			Host:    CanonicalHost(group.Host),
			Group:   group.Group,
			Changes: append([]PortChange(nil), group.Changes...),
		}
		for j := range out[i].Changes {
			change := out[i].Changes[j]
			change.Host = CanonicalHost(change.Host)
			change.Protocol = strings.ToLower(strings.TrimSpace(change.Protocol))
			change.ChangedFields = append([]string(nil), change.ChangedFields...)
			out[i].Changes[j] = change
		}
	}
	return out
}

func sortGroups(groups []HostGroup) {
	sort.Slice(groups, func(i, j int) bool { return groups[i].Host < groups[j].Host })
	for i := range groups {
		sortChanges(groups[i].Changes)
	}
}

func sortChanges(changes []PortChange) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Host != changes[j].Host {
			return changes[i].Host < changes[j].Host
		}
		return ScopeKey(changes[i].Protocol, changes[i].Port) < ScopeKey(changes[j].Protocol, changes[j].Port)
	})
}

func indexHosts(hosts []HostStatus) map[string]string {
	out := make(map[string]string, len(hosts))
	for _, host := range hosts {
		name := CanonicalHost(host.Host)
		if name == "" {
			continue
		}
		out[name] = mergeHostStatus(out[name], host.Status)
	}
	return out
}

func indexPorts(entries []PortEntry) map[string]map[string]PortEntry {
	out := make(map[string]map[string]PortEntry)
	for _, entry := range entries {
		host := CanonicalHost(entry.Host)
		if host == "" {
			continue
		}
		protocol := strings.ToLower(strings.TrimSpace(entry.Protocol))
		key := ScopeKey(protocol, entry.Port)
		ports, ok := out[host]
		if !ok {
			ports = make(map[string]PortEntry)
			out[host] = ports
		}
		if _, exists := ports[key]; exists {
			continue
		}
		entry.Host = host
		entry.Protocol = protocol
		entry.Service = copyServiceFingerprint(entry.Service)
		ports[key] = entry
	}
	return out
}

func unionHosts(hostMaps []map[string]string, portMaps ...map[string]map[string]PortEntry) []string {
	seen := make(map[string]struct{})
	for _, hosts := range hostMaps {
		for host := range hosts {
			seen[host] = struct{}{}
		}
	}
	for _, ports := range portMaps {
		for host := range ports {
			seen[host] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for host := range seen {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func sortedEntries(entries map[string]PortEntry) []PortEntry {
	out := make([]PortEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return entryLess(out[i], out[j]) })
	return out
}

func entryLess(a, b PortEntry) bool {
	if a.Host != b.Host {
		return a.Host < b.Host
	}
	ka, kb := ScopeKey(a.Protocol, a.Port), ScopeKey(b.Protocol, b.Port)
	return ka < kb
}

func sameEntryKey(a, b PortEntry) bool {
	return EntryKey(a.Host, a.Port, a.Protocol) == EntryKey(b.Host, b.Port, b.Protocol)
}

func scopeDiff(previous, current []string) (mismatch bool, prevOnly, curOnly []string) {
	prevSet, curSet := toSet(previous), toSet(current)
	for key := range prevSet {
		if _, ok := curSet[key]; !ok {
			prevOnly = append(prevOnly, key)
		}
	}
	for key := range curSet {
		if _, ok := prevSet[key]; !ok {
			curOnly = append(curOnly, key)
		}
	}
	sort.Strings(prevOnly)
	sort.Strings(curOnly)
	return len(prevOnly) > 0 || len(curOnly) > 0, prevOnly, curOnly
}

func toSet(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		out[item] = struct{}{}
	}
	return out
}

func intersectSets(a, b map[string]struct{}) map[string]struct{} {
	small, large := a, b
	if len(large) < len(small) {
		small, large = large, small
	}
	out := make(map[string]struct{}, len(small))
	for key := range small {
		if _, ok := large[key]; ok {
			out[key] = struct{}{}
		}
	}
	return out
}

func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aCopy := append([]string(nil), a...)
	bCopy := append([]string(nil), b...)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if aCopy[i] != bCopy[i] {
			return false
		}
	}
	return true
}

func ptrEntry(entry PortEntry) *PortEntry {
	copy := entry
	return &copy
}

// coverage answers "was this host inside the planned target set?" without
// materializing large ranges. Targets are reduced to non-overlapping prefixes
// and binary-searched; exact names (hostnames, unparseable entries) are kept in
// a set. Excluded ranges are checked first.
type coverage struct {
	prefixes []netip.Prefix
	names    map[string]struct{}
	excluded []netip.Prefix
	exNames  map[string]struct{}
}

func newCoverage(targets, excluded []string) *coverage {
	c := &coverage{names: map[string]struct{}{}, exNames: map[string]struct{}{}}
	for _, target := range targets {
		if prefix, ok := targetPrefix(target); ok {
			c.prefixes = append(c.prefixes, prefix)
			continue
		}
		c.names[CanonicalTarget(target)] = struct{}{}
	}
	for _, target := range excluded {
		if prefix, ok := targetPrefix(target); ok {
			c.excluded = append(c.excluded, prefix)
			continue
		}
		c.exNames[CanonicalTarget(target)] = struct{}{}
	}
	c.prefixes = dedupePrefixes(c.prefixes)
	c.excluded = dedupePrefixes(c.excluded)
	return c
}

func (c *coverage) contains(host string) bool {
	host = CanonicalHost(host)
	if host == "" {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		if _, excluded := c.exNames[host]; excluded {
			return false
		}
		_, ok := c.names[host]
		return ok
	}
	addr = addr.Unmap()
	if prefixContains(c.excluded, addr) {
		return false
	}
	return prefixContains(c.prefixes, addr)
}

// prefixContains binary-searches non-overlapping, sorted prefixes.
func prefixContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	lo, hi := 0, len(prefixes)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if prefixes[mid].Addr().Compare(addr) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return false
	}
	return prefixes[lo-1].Contains(addr)
}

// dedupePrefixes sorts prefixes and drops ones already covered by an earlier
// prefix. The result is non-overlapping, which makes binary search valid.
func dedupePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) <= 1 {
		return prefixes
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if c := prefixes[i].Addr().Compare(prefixes[j].Addr()); c != 0 {
			return c < 0
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	out := prefixes[:0]
	for _, prefix := range prefixes {
		if len(out) > 0 && out[len(out)-1].Contains(prefix.Addr()) {
			// The earlier prefix (same or broader) covers this one.
			continue
		}
		out = append(out, prefix)
	}
	return out
}

// targetPrefix converts an address or CIDR into a prefix.
func targetPrefix(target string) (netip.Prefix, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return netip.Prefix{}, false
	}
	if prefix, err := netip.ParsePrefix(target); err == nil {
		return prefix.Masked(), true
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}
