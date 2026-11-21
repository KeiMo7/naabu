package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/diff"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/stretchr/testify/require"
)

// newDiffRunner builds a connect runner whose scan scope is the given port
// list, so snapshots carry the exact probed scope the test needs.
func newDiffRunner(t *testing.T, ports string) *Runner {
	t.Helper()
	options := &Options{
		Host:      []string{"192.168.1.0/24"},
		Ports:     ports,
		ScanType:  ConnectScan,
		IPVersion: []string{"4"},
	}
	r, err := NewRunner(options)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	require.NoError(t, r.Load())
	return r
}

// buildSnapshot 把开放端口、可达主机和不确定主机都收进快照。
func TestBuildDiffSnapshotCollectsPortsAndHostStates(t *testing.T) {
	r := newConnectRunner(t)
	r.diffPlan = newDiffPlan()

	r.scanner.ScanResults.AddPort("192.0.2.10", &port.Port{
		Port: 80, Protocol: protocol.TCP,
		Service: &port.Service{Name: "http", Product: "nginx"},
	})
	// 阈值/超时跳过的主机：必须显式不确定。
	r.scanner.ScanResults.AddIp("192.0.2.11")
	r.scanner.ScanResults.AddSkipped("192.0.2.11")
	// 主机发现里活着但没有开放端口的主机。
	r.scanner.HostDiscoveryResults.AddIp("192.0.2.12")

	snapshot, err := r.buildDiffSnapshot()
	require.NoError(t, err)

	require.Contains(t, snapshot.PortScope, diff.ScopeKey("tcp", 80))
	require.Len(t, snapshot.Ports, 1)
	require.Equal(t, "192.0.2.10", snapshot.Ports[0].Host)
	require.NotNil(t, snapshot.Ports[0].Service)
	require.Equal(t, "nginx", snapshot.Ports[0].Service.Product)

	statuses := map[string]string{}
	for _, host := range snapshot.Hosts {
		statuses[host.Host] = host.Status
	}
	require.Equal(t, diff.HostReachable, statuses["192.0.2.10"])
	require.Equal(t, diff.HostUnknown, statuses["192.0.2.11"],
		"a skipped host must be recorded as unknown, not implicitly closed")
	require.Equal(t, diff.HostReachable, statuses["192.0.2.12"])
}

// 未响应任何探测的主机在快照里是 unreachable；有任一次应答的主机不是。
func TestBuildDiffSnapshotMarksSilentHostsUnreachable(t *testing.T) {
	r := newConnectRunner(t)
	r.diffPlan = newDiffPlan()

	r.scanner.ScanResults.AddPort("192.0.2.20", &port.Port{Port: 80, Protocol: protocol.TCP})
	r.noteProbeResult("192.0.2.20", true)
	r.noteProbeResult("192.0.2.21", false)
	r.noteProbeResult("192.0.2.21", false)

	snapshot, err := r.buildDiffSnapshot()
	require.NoError(t, err)

	statuses := map[string]string{}
	for _, host := range snapshot.Hosts {
		statuses[host.Host] = host.Status
	}
	require.Equal(t, diff.HostReachable, statuses["192.0.2.20"])
	require.Equal(t, diff.HostUnreachable, statuses["192.0.2.21"])
}

// 扫描中断时，planned target 覆盖集仍会写进快照，Partial 置位；比对时
// 上一轮本就没探到的端口不能算关闭。
func TestBuildDiffSnapshotMarksPlanPartialOnInterrupt(t *testing.T) {
	r := newConnectRunner(t)
	r.diffPlan = newDiffPlan()
	r.planTargets([]string{"192.168.1.0/24"})
	r.scanner.ScanResults.AddPort("192.168.1.1", &port.Port{Port: 80, Protocol: protocol.TCP})
	r.scanInterrupted.Store(true)

	snapshot, err := r.buildDiffSnapshot()
	require.NoError(t, err)
	require.True(t, snapshot.Partial)
	require.Contains(t, snapshot.Targets, "192.168.1.0/24")

	// 同一 /24 的目标主机在未探完的一轮里只能是不确定：没有开放端口不代表
	// 关闭。下一轮完整扫描后，这些主机都不会被报成 closed。
	next := diff.NewSnapshot(snapshot.PortScope)
	next.AddTarget("192.168.1.0/24")
	next.AddHost("192.168.1.1", diff.HostReachable)
	for _, host := range snapshot.Hosts {
		if host.Status == diff.HostUnknown {
			next.AddHost(host.Host, diff.HostReachable)
		}
	}

	report, err := diff.Compare(snapshot, next)
	require.NoError(t, err)
	require.Equal(t, 0, report.Summary[diff.CategoryClosed],
		"hosts left unprobed by the interrupted round must not read as closed")
}

// 端到端：第一轮写快照，第二轮基于它比对，四类结论都能跑通且结论稳定。
func TestRunDiffEndToEndTwoRounds(t *testing.T) {
	dir := t.TempDir()
	snapshotPath := filepath.Join(dir, "round1.json")
	reportPath := filepath.Join(dir, "report.json")

	// 第一轮：80 开着（http），81 开着，写出快照。扫描范围含 80/81/82，
	// 这样第二轮缺席的 81 才是确认关闭而不是未扫描。
	first := newDiffRunner(t, "80,81,82")
	first.options.DiffSnapshot = snapshotPath
	first.scanner.ScanResults.AddPort("192.168.1.1", &port.Port{
		Port: 80, Protocol: protocol.TCP, Service: &port.Service{Name: "http"},
	})
	first.scanner.ScanResults.AddPort("192.168.1.1", &port.Port{Port: 81, Protocol: protocol.TCP})
	require.NoError(t, first.runDiff())
	require.FileExists(t, snapshotPath)

	// 第二轮：80 指纹变化、81 关闭、82 新开。
	second := newDiffRunner(t, "80,81,82")
	second.options.DiffBaseline = snapshotPath
	second.options.DiffOutput = reportPath
	second.scanner.ScanResults.AddPort("192.168.1.1", &port.Port{
		Port: 80, Protocol: protocol.TCP, Service: &port.Service{Name: "http", Product: "nginx"},
	})
	second.scanner.ScanResults.AddPort("192.168.1.1", &port.Port{Port: 82, Protocol: protocol.TCP})
	require.NoError(t, second.runDiff())

	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	var report diff.Report
	require.NoError(t, json.Unmarshal(data, &report))

	changes := map[int]diff.PortChange{}
	for _, group := range report.HostChanged {
		for _, change := range group.Changes {
			changes[change.Port] = change
		}
	}
	require.Equal(t, diff.CategoryFingerprintChanged, changes[80].Category)
	require.Equal(t, diff.CategoryClosed, changes[81].Category)
	require.Equal(t, diff.CategoryNew, changes[82].Category)
	require.Equal(t, 1, report.Summary[diff.CategoryFingerprintChanged])
	require.Equal(t, 1, report.Summary[diff.CategoryClosed])
	require.Equal(t, 1, report.Summary[diff.CategoryNew])

	// 再比一次，逐字节相同（确定性）。
	reportPath2 := filepath.Join(dir, "report2.json")
	second.options.DiffOutput = reportPath2
	require.NoError(t, second.runDiff())
	data2, err := os.ReadFile(reportPath2)
	require.NoError(t, err)
	require.Equal(t, string(data), string(data2))
}

// 异常：基线缺失时明确失败，绝不静默当作全部新开。
func TestRunDiffMissingBaselineFails(t *testing.T) {
	r := newConnectRunner(t)
	r.options.DiffBaseline = filepath.Join(t.TempDir(), "nope.json")
	err := r.runDiff()
	require.Error(t, err)
	require.Contains(t, err.Error(), "previous snapshot")
}

// 异常：基线损坏时明确失败。
func TestRunDiffCorruptBaselineFails(t *testing.T) {
	baseline := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(baseline, []byte("{corrupt"), 0600))

	r := newConnectRunner(t)
	r.options.DiffBaseline = baseline
	err := r.runDiff()
	require.Error(t, err)
	require.Contains(t, err.Error(), "previous snapshot")
}

// 硬约束 4：开关关闭时 runDiff 是 no-op，主流程行为完全不变。
func TestRunDiffDisabledIsNoop(t *testing.T) {
	r := newConnectRunner(t)
	r.scanner.ScanResults.AddPort("192.168.1.1", &port.Port{Port: 80, Protocol: protocol.TCP})
	require.NoError(t, r.runDiff())
	require.Empty(t, r.options.DiffSnapshot)
	require.Empty(t, r.options.DiffBaseline)
}

// 开关打开时 diffPlan 才存在；关闭时不分配，主流程零开销。
func TestDiffPlanOnlyAllocatedWhenEnabled(t *testing.T) {
	off := newConnectRunner(t)
	require.Nil(t, off.diffPlan)
	off.noteProbeResult("192.0.2.1", true) // must not panic or allocate

	on, err := NewRunner(&Options{
		Host:         []string{"192.168.1.0/24"},
		Ports:        "80",
		ScanType:     ConnectScan,
		IPVersion:    []string{"4"},
		DiffSnapshot: filepath.Join(t.TempDir(), "round.json"),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = on.Close() })
	require.NotNil(t, on.diffPlan)
}

// 校验：-diff-output 单独出现、基线不存在、路径互相覆盖都被拒绝。
func TestValidateDiffOptions(t *testing.T) {
	r := newConnectRunner(t)

	r.options.DiffOutput = filepath.Join(t.TempDir(), "r.json")
	r.options.DiffBaseline = ""
	require.Error(t, r.options.validateDiffOptions())

	r.options.DiffBaseline = filepath.Join(t.TempDir(), "missing.json")
	require.Error(t, r.options.validateDiffOptions())

	baseline := filepath.Join(t.TempDir(), "base.json")
	baseSnapshot := diff.NewSnapshot([]string{diff.ScopeKey("tcp", 80)})
	require.NoError(t, diff.WriteSnapshot(baseline, baseSnapshot))
	r.options.DiffBaseline = baseline
	require.NoError(t, r.options.validateDiffOptions())

	corrupt := filepath.Join(t.TempDir(), "corrupt.json")
	require.NoError(t, os.WriteFile(corrupt, []byte("{oops"), 0600))
	r.options.DiffBaseline = corrupt
	require.Error(t, r.options.validateDiffOptions(), "a corrupt baseline is rejected up front")

	r.options.DiffBaseline = baseline
	r.options.DiffSnapshot = baseline
	require.Error(t, r.options.validateDiffOptions(), "writing over the baseline is rejected")

	r.options.DiffSnapshot = ""
	r.options.DiffOutput = baseline
	require.Error(t, r.options.validateDiffOptions(), "writing the report over the baseline is rejected")
}

// 中断标记只在父上下文被取消（SIGINT/中止）或 max-runtime 到期时置位；
// 扫描自身 stopScan 的正常取消不算中断。
func TestMarkInterrupted(t *testing.T) {
	r := newConnectRunner(t)

	parent, cancelParent := context.WithCancel(context.Background())
	scanCtx, stopScan := context.WithCancel(parent)
	stopScan() // the scan's own teardown
	r.markInterrupted(scanCtx, parent)
	require.False(t, r.scanInterrupted.Load())

	cancelParent()
	r.markInterrupted(parent, parent)
	require.True(t, r.scanInterrupted.Load())
}

func TestMarkInterruptedOnMaxRuntime(t *testing.T) {
	r := newConnectRunner(t)
	prev := maxRuntimeWarning.Load()
	noop := func(time.Duration) {}
	maxRuntimeWarning.Store(&noop)
	t.Cleanup(func() { maxRuntimeWarning.Store(prev) })

	r.options.MaxRuntime = 5 * time.Millisecond
	parent := context.Background()
	scanCtx, stop := r.withMaxRuntime(parent)
	defer stop()
	<-scanCtx.Done()

	r.markInterrupted(scanCtx, parent)
	require.True(t, r.scanInterrupted.Load())
}

// 探测应答判定：拒绝/不可达算"主机有应答"，超时不算。
func TestIsProbeAnswered(t *testing.T) {
	require.True(t, isProbeAnswered(nil))
	require.False(t, isProbeAnswered(os.ErrDeadlineExceeded))
	require.False(t, isProbeAnswered(context.DeadlineExceeded))
}
