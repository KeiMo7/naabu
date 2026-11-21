package runner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/diff"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
)

// diffPlan records the side-channel evidence the diff snapshot needs in
// addition to the final open-port inventory. None of it is consulted by the
// probe pipeline or the single-round output; it is written only while a diff
// flag is enabled and read only once the scan has settled.
type diffPlan struct {
	mu sync.Mutex
	// targets holds the planned IPs/CIDRs, captured from the same target set
	// the probe loop used.
	targets []string
	// probed counts completed connect probes per host.
	probed map[string]int
	// answered counts connect probes that produced an answer from the host
	// (open, refused or reset), i.e. evidence the host is reachable.
	answered map[string]int
}

func newDiffPlan() *diffPlan {
	return &diffPlan{
		probed:   make(map[string]int),
		answered: make(map[string]int),
	}
}

// resetDiffPlan prepares a fresh plan for a new enumeration on a reused Runner.
func (r *Runner) resetDiffPlan() {
	if r.diffPlan == nil {
		return
	}
	r.diffPlan = newDiffPlan()
}

// noteProbeResult records one completed connect probe and whether the host
// answered it. It is called from the probe hot path and is a no-op without a
// diff flag, so a normal scan pays nothing.
func (r *Runner) noteProbeResult(host string, answered bool) {
	if r.diffPlan == nil {
		return
	}
	host = diff.CanonicalHost(host)
	if host == "" {
		return
	}
	r.diffPlan.mu.Lock()
	r.diffPlan.probed[host]++
	if answered {
		r.diffPlan.answered[host]++
	}
	r.diffPlan.mu.Unlock()
}

// planTargets replaces the planned target set. It is called once the target
// space is final and before probing starts.
func (r *Runner) planTargets(targets []string) {
	if r.diffPlan == nil {
		return
	}
	r.diffPlan.mu.Lock()
	r.diffPlan.targets = append([]string(nil), targets...)
	r.diffPlan.mu.Unlock()
}

// addPlannedTarget appends one planned target (CIDR or address).
func (r *Runner) addPlannedTarget(target string) {
	if r.diffPlan == nil || target == "" {
		return
	}
	r.diffPlan.mu.Lock()
	r.diffPlan.targets = append(r.diffPlan.targets, target)
	r.diffPlan.mu.Unlock()
}

// shouldComputeDeadHosts reports whether dead hosts must be calculated even
// without -show-dead because the diff layer needs host-level evidence.
func (r *Runner) shouldComputeDeadHosts() bool {
	return r.diffPlan != nil
}

// recordPlannedTargets captures the final coalesced target space of a normal
// (non-stream) scan: the same CIDR set the probe loop indexes over, plus any
// explicit ip:port targets.
func (r *Runner) recordPlannedTargets(targetsV4, targetsV6 []*net.IPNet, targetsWithPort []string) {
	if r.diffPlan == nil {
		return
	}
	targets := make([]string, 0, len(targetsV4)+len(targetsV6)+len(targetsWithPort))
	for _, cidr := range append(append([]*net.IPNet(nil), targetsV4...), targetsV6...) {
		if cidr != nil {
			targets = append(targets, cidr.String())
		}
	}
	for _, target := range targetsWithPort {
		if host, _, err := net.SplitHostPort(target); err == nil {
			targets = append(targets, host)
		}
	}
	r.planTargets(targets)
}

// markInterrupted records that the probe-sending phase ended before covering
// every target. The scan context is always cancelled by its own stop function,
// so the local cause is only meaningful for the max-runtime budget; a genuine
// interrupt is the parent context being cancelled (SIGINT/abort). It is called
// after the single-round output, so it cannot affect existing behaviour; only
// the diff snapshot reads it.
func (r *Runner) markInterrupted(scanCtx, parentCtx context.Context) {
	if scanCtx != nil && errors.Is(context.Cause(scanCtx), errMaxRuntime) {
		r.scanInterrupted.Store(true)
		return
	}
	if parentCtx != nil && parentCtx.Err() != nil {
		r.scanInterrupted.Store(true)
	}
}

// runDiff is the round-over-round side layer. It runs strictly after the
// normal single-round output: the probe pipeline, its output files and the
// process exit code are untouched. When neither diff flag is set it is a
// no-op. Failures are returned to the caller but never alter the scan results
// already written.
func (r *Runner) runDiff() error {
	if !r.options.DiffEnabled() {
		return nil
	}

	current, err := r.buildDiffSnapshot()
	if err != nil {
		return err
	}

	if r.options.DiffSnapshot != "" {
		if err := diff.WriteSnapshot(r.options.DiffSnapshot, current); err != nil {
			return err
		}
		gologger.Info().Msgf("Diff snapshot written to %s\n", r.options.DiffSnapshot)
	}

	if r.options.DiffBaseline == "" {
		return nil
	}

	previous := r.options.diffBaseline
	if previous == nil || r.options.diffBaselinePath != r.options.DiffBaseline {
		// Option validation normally decodes the baseline before the scan; an
		// SDK caller that set the path later gets the same explicit failure
		// here instead of silently comparing against an empty world.
		previous, err = diff.ReadSnapshot(r.options.DiffBaseline)
		if err != nil {
			return err
		}
	}

	report, err := diff.Compare(previous, current)
	if err != nil {
		return err
	}

	if report.ScopeMismatch {
		gologger.Warning().Msgf("%s\n", report.ScopeWarning)
	}

	if r.options.DiffOutput == "" {
		return diff.EncodeReport(os.Stdout, report)
	}
	if err := diff.WriteReport(r.options.DiffOutput, report); err != nil {
		return err
	}
	gologger.Info().Msgf("Diff report written to %s\n", r.options.DiffOutput)
	return nil
}

// buildDiffSnapshot turns the settled scan state into a round-stable snapshot.
// Open ports come from ScanResults; host states come from explicit findings in
// precedence order: dead hosts (unreachable), hosts that answered, then hosts
// left unprobed by an interrupted or threshold-truncated scan (unknown).
func (r *Runner) buildDiffSnapshot() (*diff.Snapshot, error) {
	snapshot := diff.NewSnapshot(r.diffScopeKeys())
	snapshot.Partial = r.scanInterrupted.Load()

	for _, target := range r.diffExcludedIps {
		snapshot.AddExcluded(target)
	}

	// Open ports are definitive evidence of reachability for the ports found.
	r.scanner.ScanResults.ForEachHostPorts(func(ip string, ports []*port.Port) {
		snapshot.AddHost(ip, diff.HostReachable)
		for _, p := range ports {
			snapshot.AddPort(diff.PortEntry{
				Host:     ip,
				Port:     p.Port,
				Protocol: p.Protocol.String(),
				TLS:      p.TLS,
				Service:  toServiceFingerprint(p.Service),
			})
		}
	})

	// A partial host (port threshold / max-runtime) keeps whatever ports it did
	// find, but is explicitly uncertain so its missing ports are not closures.
	// This is host-local: a threshold cut-off on one host does not make every
	// other host's coverage incomplete.
	for _, ip := range r.scanner.ScanResults.GetSkippedIPs() {
		snapshot.AddHost(ip, diff.HostUnknown)
	}

	// Host discovery evidence: alive hosts with no open ports, and dead hosts.
	for ip := range r.scanner.HostDiscoveryResults.GetIPs() {
		if !r.isExcluded(ip) {
			snapshot.AddHost(ip, diff.HostReachable)
		}
	}
	for _, ip := range r.scanner.HostDiscoveryResults.GetDeadHosts() {
		snapshot.AddHost(ip, diff.HostUnreachable)
	}

	if plan := r.diffPlan; plan != nil {
		plan.mu.Lock()
		answered := make([]string, 0, len(plan.answered))
		unreachable := make([]string, 0, len(plan.probed))
		for host, probes := range plan.probed {
			if probes == 0 {
				continue
			}
			if plan.answered[host] > 0 {
				answered = append(answered, host)
				continue
			}
			unreachable = append(unreachable, host)
		}
		plan.mu.Unlock()

		// An answered probe (even a refusal) proves the host is alive, so a
		// fully covered host with zero open ports is still reachable rather
		// than absent.
		for _, host := range answered {
			snapshot.AddHost(host, diff.HostReachable)
		}
		// Hosts that never answered any probe in a scan without host discovery
		// are unreachable, not "reachable with every port closed".
		discoveryRan := r.scanner.HostDiscoveryResults.HasIPS()
		if !discoveryRan {
			for _, host := range unreachable {
				snapshot.AddHost(host, diff.HostUnreachable)
			}
		}
	}

	// Stream mode closes its target channel before probing; capture the planned
	// space now so the snapshot declares what this round covered.
	if r.diffPlan != nil {
		r.diffPlan.mu.Lock()
		planned := append([]string(nil), r.diffPlan.targets...)
		r.diffPlan.mu.Unlock()
		for _, target := range planned {
			snapshot.AddTarget(target)
		}
	}
	if len(snapshot.Targets) == 0 {
		for _, target := range r.plannedDiffTargets() {
			snapshot.AddTarget(target)
		}
	}

	// An interrupted round leaves planned targets that were never probed. A
	// host that produced some open ports may still have ports that were never
	// probed, so interruption makes every reachable host without explicit dead
	// evidence uncertain. Enumerate the (bounded) target space and add the
	// remaining targets as explicit unknowns.
	// An interrupted round leaves planned targets that were never probed.
	// Materialize them as explicit unknown hosts so a consumer of the snapshot
	// alone can see the uncertainty; the round-level Partial flag still marks
	// hosts that did produce results as incomplete coverage. Enumeration is
	// bounded so a /8 never inflates the snapshot.
	if snapshot.Partial {
		r.markUnprobedTargetsUnknown(snapshot)
	}

	return snapshot, nil
}

// diffUnknownEnumerationCap bounds how many addresses an interrupted round
// materializes as explicit "unknown" hosts. Beyond it the Partial flag alone
// carries the meaning; enumerating a /8 would cost more memory than the rest
// of the snapshot combined.
const diffUnknownEnumerationCap = 1 << 20

// markUnprobedTargetsUnknown adds an unknown state for every planned target
// address that has no state yet. Excluded addresses are skipped. When a target
// range is too large to enumerate under the cap, enumeration stops and the
// snapshot-level Partial flag remains the protection.
func (r *Runner) markUnprobedTargetsUnknown(snapshot *diff.Snapshot) {
	known := make(map[string]struct{}, len(snapshot.Hosts))
	for _, host := range snapshot.Hosts {
		known[diff.CanonicalHost(host.Host)] = struct{}{}
	}

	budget := int64(diffUnknownEnumerationCap)
	for _, target := range snapshot.Targets {
		prefix, err := netip.ParsePrefix(target)
		if err != nil {
			if addr, addrErr := netip.ParseAddr(target); addrErr == nil {
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			} else {
				continue
			}
		}
		prefix = prefix.Masked()
		hostBits := prefix.Addr().BitLen() - prefix.Bits()
		if hostBits < 0 {
			continue
		}
		count := int64(1) << uint(hostBits)
		if hostBits > 20 || count > budget {
			return
		}
		budget -= count
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			ip := addr.String()
			if r.isExcluded(ip) {
				continue
			}
			if _, seen := known[ip]; seen {
				continue
			}
			known[ip] = struct{}{}
			snapshot.AddHost(ip, diff.HostUnknown)
		}
	}
}

// diffScopeKeys renders the actually probed port set as diff scope keys. The
// list is the post-parse, post-exclusion port slice used by the scanner, so it
// reflects exactly what this round probed regardless of the -p spelling.
func (r *Runner) diffScopeKeys() []string {
	keys := make([]string, 0, len(r.scanner.Ports))
	for _, p := range r.scanner.Ports {
		keys = append(keys, diff.ScopeKey(p.Protocol.String(), p.Port))
	}
	return keys
}

// plannedDiffTargets returns the target list captured before probing. When a
// caller never captured one (e.g. an SDK-driven partial run), it falls back to
// the in-memory target store so the snapshot still declares coverage.
func (r *Runner) plannedDiffTargets() []string {
	if r.diffPlan != nil {
		r.diffPlan.mu.Lock()
		targets := append([]string(nil), r.diffPlan.targets...)
		r.diffPlan.mu.Unlock()
		if len(targets) > 0 {
			return targets
		}
	}
	var targets []string
	r.scanner.IPRanger.Hosts.Scan(func(key, _ []byte) error {
		targets = append(targets, string(key))
		return nil
	})
	return targets
}

// isProbeAnswered reports whether a failed connect probe still produced a
// definitive answer from the host. A refused or unreachable TCP error proves
// the host is alive (its stack replied); a timeout or a local resource error
// proves nothing about the host.
func isProbeAnswered(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return false
	}
	// Connection refused, network unreachable, host unreachable and reset all
	// mean the host's stack answered (or the network rejected the probe).
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

// toServiceFingerprint copies the identity-relevant service fields into a
// value-owned diff structure.
func toServiceFingerprint(service *port.Service) *diff.ServiceFingerprint {
	if service == nil {
		return nil
	}
	return &diff.ServiceFingerprint{
		Name:        service.Name,
		Product:     service.Product,
		Version:     service.Version,
		ServiceFP:   service.ServiceFP,
		Banner:      service.Banner,
		Tunnel:      service.Tunnel,
		Method:      service.Method,
		Hostname:    service.Hostname,
		OSType:      service.OSType,
		DeviceType:  service.DeviceType,
		ExtraInfo:   service.ExtraInfo,
		HighVersion: service.HighVersion,
		LowVersion:  service.LowVersion,
		Proto:       service.Proto,
		RPCNum:      service.RPCNum,
		Confidence:  service.Confidence,
		CPEs:        append([]string(nil), service.CPEs...),
	}
}
