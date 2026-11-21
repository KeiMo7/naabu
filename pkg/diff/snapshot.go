// Package diff implements round-over-round comparison of naabu port scans.
//
// The diff layer is strictly a side layer: it never participates in probing or
// in the single-round output path. A scan run can persist a self-describing
// Snapshot of its findings; a later run compares its fresh Snapshot against a
// previous one and produces a deterministic Report. Every identity used here
// (host + port + protocol) is free of scan time, source address and probe
// order, so the same two snapshots always compare to the same bytes.
package diff

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// FormatVersion is bumped when the on-disk layout changes in an incompatible
// way. A snapshot carrying another version is rejected instead of being
// misread.
const FormatVersion = 1

// SnapshotFormatVersion is kept as an alias for FormatVersion.
const SnapshotFormatVersion = FormatVersion

// Host states recorded by a scan. A host is always in exactly one state.
const (
	// HostReachable answered discovery, has at least one reported open port, or
	// was fully covered by a completed scan (even with no open ports).
	HostReachable = "reachable"
	// HostUnreachable was probed during discovery and never answered.
	HostUnreachable = "unreachable"
	// HostUnknown was not fully covered (timeout, max-runtime, abort, port
	// threshold): its missing ports are unknown, not closed.
	HostUnknown = "unknown"
)

// ServiceFingerprint holds the identity-relevant fields of a service. It is a
// value type so snapshots share no pointers with the live scan result.
type ServiceFingerprint struct {
	Name        string   `json:"name,omitempty"`
	Product     string   `json:"product,omitempty"`
	Version     string   `json:"version,omitempty"`
	ServiceFP   string   `json:"service_fp,omitempty"`
	Banner      string   `json:"banner,omitempty"`
	Tunnel      string   `json:"tunnel,omitempty"`
	Method      string   `json:"method,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	OSType      string   `json:"os_type,omitempty"`
	DeviceType  string   `json:"device_type,omitempty"`
	ExtraInfo   string   `json:"extra_info,omitempty"`
	HighVersion string   `json:"high_version,omitempty"`
	LowVersion  string   `json:"low_version,omitempty"`
	Proto       string   `json:"proto,omitempty"`
	RPCNum      string   `json:"rpc_num,omitempty"`
	Confidence  int      `json:"confidence,omitempty"`
	CPEs        []string `json:"cpes,omitempty"`
}

// PortEntry is one host+port+protocol observation. The JSON field order below
// is the canonical wire order; entries are sorted before being written so a
// snapshot is byte-for-byte reproducible.
type PortEntry struct {
	Host     string              `json:"host"`
	Port     int                 `json:"port"`
	Protocol string              `json:"protocol"`
	TLS      bool                `json:"tls,omitempty"`
	Service  *ServiceFingerprint `json:"service,omitempty"`
}

// HostStatus records the coverage state of one target host.
type HostStatus struct {
	Host   string `json:"host"`
	Status string `json:"status"`
}

// Snapshot is the self-describing, round-stable record of one scan.
type Snapshot struct {
	// FormatVersion lets readers reject layouts they cannot understand.
	FormatVersion int `json:"format_version"`
	// PortScope is the sorted "proto/port" set the scan actually probed. It is
	// what makes "we did not scan this" distinguishable from "this was closed".
	PortScope []string `json:"port_scope"`
	// Targets is the optional set of target IPs/CIDRs planned this round. It
	// lets a comparison tell an existing target that merely had no open ports
	// from a genuinely new target, without materializing every address of a
	// large range. Older snapshots without this field fall back to the host
	// list, which is why the field is optional.
	Targets []string `json:"targets,omitempty"`
	// Excluded is the optional set of excluded IPs/CIDRs. Addresses inside a
	// target range but excluded this round are not considered covered.
	Excluded []string `json:"excluded,omitempty"`
	// Partial is set when the probe-sending phase ended before every planned
	// target was fully covered (max-runtime, interrupt). Targets that carry no
	// explicit host state then compare as unknown, not as reachable with no
	// open ports.
	Partial bool `json:"partial,omitempty"`
	// Hosts holds the state of every host with an explicit observation.
	Hosts []HostStatus `json:"hosts"`
	// Ports holds only confirmed open ports.
	Ports []PortEntry `json:"ports"`

	// Build-time indices. They are not serialized and are rebuilt lazily after
	// decoding, so building a 100k-entry snapshot stays linear instead of
	// scanning the slices for every insert.
	hostIndex map[string]int
	portIndex map[string]int
}

// NewSnapshot creates an empty snapshot stamped with the current format
// version and the given probed scope.
func NewSnapshot(portScope []string) *Snapshot {
	return &Snapshot{
		FormatVersion: SnapshotFormatVersion,
		PortScope:     normalizeScope(portScope),
		hostIndex:     make(map[string]int),
		portIndex:     make(map[string]int),
	}
}

// AddHost records a host in the given state. Repeated calls for one host merge
// deterministically: unreachable > unknown > reachable, independent of arrival
// order.
func (s *Snapshot) AddHost(host, status string) {
	host = CanonicalHost(host)
	if host == "" || !validHostStatus(status) {
		return
	}
	s.ensureIndices()
	if i, ok := s.hostIndex[host]; ok {
		s.Hosts[i].Status = mergeHostStatus(s.Hosts[i].Status, status)
		return
	}
	s.hostIndex[host] = len(s.Hosts)
	s.Hosts = append(s.Hosts, HostStatus{Host: host, Status: status})
}

// AddPort records a confirmed open port. Duplicate identities overwrite, which
// keeps repeated calls idempotent.
func (s *Snapshot) AddPort(entry PortEntry) {
	entry.Host = CanonicalHost(entry.Host)
	entry.Protocol = strings.ToLower(strings.TrimSpace(entry.Protocol))
	if entry.Host == "" || !validPortNumber(entry.Port) || entry.Protocol == "" {
		return
	}
	entry.Service = copyServiceFingerprint(entry.Service)
	key := EntryKey(entry.Host, entry.Port, entry.Protocol)
	s.ensureIndices()
	if i, ok := s.portIndex[key]; ok {
		s.Ports[i] = entry
		return
	}
	s.portIndex[key] = len(s.Ports)
	s.Ports = append(s.Ports, entry)
}

func (s *Snapshot) ensureIndices() {
	if s.hostIndex == nil {
		s.hostIndex = make(map[string]int, len(s.Hosts))
		for i := range s.Hosts {
			host := CanonicalHost(s.Hosts[i].Host)
			if host == "" {
				continue
			}
			if j, ok := s.hostIndex[host]; ok {
				s.Hosts[j].Status = mergeHostStatus(s.Hosts[j].Status, s.Hosts[i].Status)
				continue
			}
			s.hostIndex[host] = i
		}
	}
	if s.portIndex == nil {
		s.portIndex = make(map[string]int, len(s.Ports))
		for i := range s.Ports {
			key := EntryKey(s.Ports[i].Host, s.Ports[i].Port, s.Ports[i].Protocol)
			if _, ok := s.portIndex[key]; !ok {
				s.portIndex[key] = i
			}
		}
	}
}

// HasHost reports whether host already has an explicit state.
func (s *Snapshot) HasHost(host string) bool {
	s.ensureIndices()
	_, ok := s.hostIndex[CanonicalHost(host)]
	return ok
}

// AddTarget records a planned target address or CIDR.
func (s *Snapshot) AddTarget(target string) {
	if canonical := CanonicalTarget(target); canonical != "" {
		s.Targets = append(s.Targets, canonical)
	}
}

// AddExcluded records an excluded address or CIDR.
func (s *Snapshot) AddExcluded(target string) {
	if canonical := CanonicalTarget(target); canonical != "" {
		s.Excluded = append(s.Excluded, canonical)
	}
}

// EntryKey is the cross-round identity of a port entry. It deliberately
// contains only the host, protocol and port number: no timestamp, source
// address or probe ordering, so the same endpoint keeps the same key across
// rounds.
func EntryKey(host string, port int, protocol string) string {
	return fmt.Sprintf("%s|%s/%d", CanonicalHost(host), strings.ToLower(strings.TrimSpace(protocol)), port)
}

// ScopeKey is the identity of a probed port within the scan scope.
func ScopeKey(protocol string, port int) string {
	return fmt.Sprintf("%s/%d", strings.ToLower(strings.TrimSpace(protocol)), port)
}

// CanonicalHost normalizes a host string for stable cross-round identity.
// IP literals (including IPv4-mapped IPv6) are rendered in their canonical
// form; hostnames are lowercased and stripped of a trailing dot.
func CanonicalHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// CanonicalTarget normalizes a CIDR or address. CIDRs are masked to their
// network address; addresses are canonicalized like hosts. Unparseable entries
// are returned lowercased/trimmed so they still sort deterministically.
func CanonicalTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if prefix, err := netip.ParsePrefix(target); err == nil {
		return prefix.Masked().String()
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		return addr.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(target, "."))
}

// WriteSnapshot sorts every collection for reproducibility and writes the
// snapshot as pretty JSON. The file is created atomically: data goes to a
// temp file in the same directory and is renamed only once the full content
// is on disk, so a failure never leaves a half-written snapshot.
func WriteSnapshot(path string, snapshot *Snapshot) error {
	if path == "" {
		return fmt.Errorf("snapshot path is empty")
	}
	if snapshot == nil {
		return fmt.Errorf("cannot write a nil snapshot")
	}
	data, err := snapshot.MarshalCanonical()
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0600)
}

// MarshalCanonical returns the canonical pretty JSON form of the snapshot. It
// does not mutate the snapshot, so a caller may keep using it afterwards.
func (s *Snapshot) MarshalCanonical() ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("cannot encode a nil snapshot")
	}
	data, err := json.MarshalIndent(s.canonicalCopy(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode snapshot: %w", err)
	}
	return append(data, '\n'), nil
}

// EncodeSnapshot writes the canonical JSON form to a writer.
func EncodeSnapshot(writer io.Writer, snapshot *Snapshot) error {
	data, err := snapshot.MarshalCanonical()
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

// ReadSnapshot loads and validates a snapshot. A missing file, malformed JSON
// or an unsupported format version all produce explicit errors; callers must
// never treat a read failure as "the previous round had nothing".
func ReadSnapshot(path string) (*Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("previous snapshot %q: %w", path, err)
	}
	defer file.Close()

	snapshot, err := DecodeSnapshot(bufio.NewReader(file))
	if err != nil {
		return nil, fmt.Errorf("previous snapshot %q: %w", path, err)
	}
	return snapshot, nil
}

// DecodeSnapshot reads a snapshot from a reader without touching the
// filesystem, which keeps the comparison logic independently testable. The
// decoder pulls the JSON stream in chunks rather than buffering the file, so
// large snapshots (100k+ entries) stay proportional to the decoded inventory.
func DecodeSnapshot(reader io.Reader) (*Snapshot, error) {
	snapshot := &Snapshot{}
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(snapshot); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	if snapshot.FormatVersion != SnapshotFormatVersion {
		return nil, fmt.Errorf("unsupported snapshot format version %d (expected %d)", snapshot.FormatVersion, SnapshotFormatVersion)
	}
	if err := snapshot.validate(); err != nil {
		return nil, err
	}
	return snapshot.canonicalCopy(), nil
}

func (s *Snapshot) validate() error {
	for _, host := range s.Hosts {
		if CanonicalHost(host.Host) == "" {
			return fmt.Errorf("invalid host entry: empty host")
		}
		if !validHostStatus(host.Status) {
			return fmt.Errorf("invalid host status %q for %q", host.Status, host.Host)
		}
	}
	for _, key := range s.PortScope {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("invalid port scope: empty key")
		}
	}
	seen := make(map[string]struct{}, len(s.Ports))
	for _, entry := range s.Ports {
		if CanonicalHost(entry.Host) == "" || !validPortNumber(entry.Port) || strings.TrimSpace(entry.Protocol) == "" {
			return fmt.Errorf("invalid port entry: %+v", entry)
		}
		key := EntryKey(entry.Host, entry.Port, entry.Protocol)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate port entry %s", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validPortNumber(port int) bool {
	return port > 0 && port <= 65535
}

// canonicalCopy returns a canonicalized deep copy: every collection sorted and
// deduplicated, hosts and protocols normalized. Working on a copy keeps
// Compare pure and makes serialization independent of caller ordering.
func (s *Snapshot) canonicalCopy() *Snapshot {
	if s == nil {
		return nil
	}
	out := &Snapshot{
		FormatVersion: s.FormatVersion,
		PortScope:     normalizeScope(s.PortScope),
		Targets:       normalizeTargets(s.Targets),
		Excluded:      normalizeTargets(s.Excluded),
		Partial:       s.Partial,
	}

	hosts := make(map[string]string, len(s.Hosts))
	for _, host := range s.Hosts {
		canonical := CanonicalHost(host.Host)
		if canonical == "" || !validHostStatus(host.Status) {
			continue
		}
		hosts[canonical] = mergeHostStatus(hosts[canonical], host.Status)
	}
	out.Hosts = make([]HostStatus, 0, len(hosts))
	for host, status := range hosts {
		out.Hosts = append(out.Hosts, HostStatus{Host: host, Status: status})
	}
	sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].Host < out.Hosts[j].Host })

	entries := make([]PortEntry, 0, len(s.Ports))
	for _, entry := range s.Ports {
		entry.Host = CanonicalHost(entry.Host)
		entry.Protocol = strings.ToLower(strings.TrimSpace(entry.Protocol))
		entry.Service = copyServiceFingerprint(entry.Service)
		if entry.Host == "" || !validPortNumber(entry.Port) || entry.Protocol == "" {
			continue
		}
		if entry.Service != nil {
			sort.Strings(entry.Service.CPEs)
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entryLess(entries[i], entries[j]) })
	out.Ports = entries[:0]
	for _, entry := range entries {
		if n := len(out.Ports); n > 0 && sameEntryKey(out.Ports[n-1], entry) {
			continue
		}
		out.Ports = append(out.Ports, entry)
	}
	return out
}

func copyServiceFingerprint(s *ServiceFingerprint) *ServiceFingerprint {
	if s == nil {
		return nil
	}
	cp := *s
	cp.CPEs = append([]string(nil), s.CPEs...)
	return &cp
}

func validHostStatus(status string) bool {
	return status == HostReachable || status == HostUnreachable || status == HostUnknown
}

// mergeHostStatus resolves repeated observations of one host. The order is
// fixed so the result never depends on arrival order:
//
//	unknown > reachable > unreachable
//
// Unknown wins because a host that was cut short cannot vouch for its ports
// even if it answered something. Reachable beats unreachable because an
// observed open port (or an answered probe) is stronger liveness evidence than
// a discovery timeout, and a false "host down" would hide real ports.
func mergeHostStatus(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if hostStatusRank(a) >= hostStatusRank(b) {
		return a
	}
	return b
}

func hostStatusRank(status string) int {
	switch status {
	case HostUnknown:
		return 3
	case HostReachable:
		return 2
	case HostUnreachable:
		return 1
	default:
		return 0
	}
}

// normalizeScope deduplicates and sorts a scope list.
func normalizeScope(scope []string) []string {
	seen := make(map[string]struct{}, len(scope))
	out := make([]string, 0, len(scope))
	for _, key := range scope {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// normalizeTargets canonicalizes an IP/CIDR list and sorts it.
func normalizeTargets(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		canonical := CanonicalTarget(item)
		if canonical == "" {
			continue
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out
}
