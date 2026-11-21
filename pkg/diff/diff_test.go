package diff

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func tcpPort(host string, port int, service *ServiceFingerprint) PortEntry {
	return PortEntry{Host: host, Port: port, Protocol: "tcp", Service: service}
}

func httpService() *ServiceFingerprint {
	return &ServiceFingerprint{Name: "http", Product: "nginx", Version: "1.25"}
}

// fullScope builds a scope containing every tcp port used in the tests, so
// cases that do not care about scope mismatch start from identical scopes.
func fullScope(ports ...int) []string {
	out := make([]string, 0, len(ports))
	for _, port := range ports {
		out = append(out, ScopeKey("tcp", port))
	}
	return out
}

func findChange(t *testing.T, groups []HostGroup, host string, port int, protocol string) PortChange {
	t.Helper()
	for _, group := range groups {
		if group.Host != host {
			continue
		}
		for _, change := range group.Changes {
			if change.Port == port && change.Protocol == protocol {
				return change
			}
		}
	}
	require.Failf(t, "change not found", "%s %s/%d", host, protocol, port)
	return PortChange{}
}

// 验收 1：纯新开 — 上一轮关着（有主机记录、无该端口），这一轮开着。
func TestComparePureNewPort(t *testing.T) {
	scope := fullScope(80, 8080)
	previous := NewSnapshot(scope)
	previous.AddHost("192.0.2.10", HostReachable)
	previous.AddPort(tcpPort("192.0.2.10", 80, nil))

	current := NewSnapshot(scope)
	current.AddHost("192.0.2.10", HostReachable)
	current.AddPort(tcpPort("192.0.2.10", 80, nil))
	current.AddPort(tcpPort("192.0.2.10", 8080, nil))

	report, err := Compare(previous, current)
	require.NoError(t, err)
	require.False(t, report.ScopeMismatch)

	change := findChange(t, report.HostChanged, "192.0.2.10", 8080, "tcp")
	require.Equal(t, CategoryNew, change.Category)
	require.Equal(t, 1, report.Summary[CategoryNew])
	require.Equal(t, 1, report.Summary[CategoryUnchanged])
	require.Equal(t, 0, report.Summary[CategoryClosed])
}

// 验收 1：纯关闭 — 上一轮开着，这一轮确认关着（同一扫描范围）。
func TestComparePureClosedPort(t *testing.T) {
	scope := fullScope(80, 8080)
	previous := NewSnapshot(scope)
	previous.AddHost("192.0.2.10", HostReachable)
	previous.AddPort(tcpPort("192.0.2.10", 8080, nil))

	current := NewSnapshot(scope)
	current.AddHost("192.0.2.10", HostReachable)
	current.AddPort(tcpPort("192.0.2.10", 80, nil))

	report, err := Compare(previous, current)
	require.NoError(t, err)

	change := findChange(t, report.HostChanged, "192.0.2.10", 8080, "tcp")
	require.Equal(t, CategoryClosed, change.Category)
	require.Nil(t, change.Current)
	require.NotNil(t, change.Previous)
	require.Equal(t, 1, report.Summary[CategoryClosed])
}

// 验收 1：超时转确认 — 上一轮主机未探完（unknown），这一轮探到了，
// 必须识别为不确定的消解，而不是新开。
func TestCompareTimeoutTurnedConfirmed(t *testing.T) {
	scope := fullScope(80, 8080)
	previous := NewSnapshot(scope)
	previous.AddHost("192.0.2.10", HostUnknown)
	previous.AddPort(tcpPort("192.0.2.10", 80, nil))

	current := NewSnapshot(scope)
	current.AddHost("192.0.2.10", HostReachable)
	current.AddPort(tcpPort("192.0.2.10", 80, nil))
	current.AddPort(tcpPort("192.0.2.10", 8080, nil))

	report, err := Compare(previous, current)
	require.NoError(t, err)

	for _, group := range report.HostChanged {
		for _, change := range group.Changes {
			require.NotEqual(t, CategoryNew, change.Category,
				"unknown host ports must never be classified as new")
		}
	}
	require.Equal(t, 2, report.Summary[CategoryUncertainResolved])
	require.Equal(t, 0, report.Summary[CategoryNew])
	require.Equal(t, 0, report.Summary[CategoryClosed])
}

// 验收 1：指纹变化 — 同一端口两轮都开，但服务指纹变了，算变化并标出字段。
func TestCompareFingerprintChange(t *testing.T) {
	scope := fullScope(80)
	previous := NewSnapshot(scope)
	previous.AddHost("192.0.2.10", HostReachable)
	previous.AddPort(tcpPort("192.0.2.10", 80, httpService()))

	current := NewSnapshot(scope)
	current.AddHost("192.0.2.10", HostReachable)
	current.AddPort(tcpPort("192.0.2.10", 80, &ServiceFingerprint{Name: "http", Product: "apache", Version: "2.4"}))

	report, err := Compare(previous, current)
	require.NoError(t, err)

	change := findChange(t, report.HostChanged, "192.0.2.10", 80, "tcp")
	require.Equal(t, CategoryFingerprintChanged, change.Category)
	require.ElementsMatch(t, []string{"product", "version"}, change.ChangedFields)
	require.Equal(t, 1, report.Summary[CategoryFingerprintChanged])
	// 指纹变化不算一开一关。
	require.Equal(t, 0, report.Summary[CategoryNew])
	require.Equal(t, 0, report.Summary[CategoryClosed])
}

// 形态 3：上一轮在线、这一轮不可达 — 归主机不可达，不算端口全关。
func TestCompareHostBecameUnreachable(t *testing.T) {
	scope := fullScope(80)
	previous := NewSnapshot(scope)
	previous.AddHost("192.0.2.10", HostReachable)
	previous.AddPort(tcpPort("192.0.2.10", 80, nil))

	current := NewSnapshot(scope)
	current.AddHost("192.0.2.10", HostUnreachable)

	report, err := Compare(previous, current)
	require.NoError(t, err)

	require.Len(t, report.HostUnreachable, 1)
	require.Equal(t, "192.0.2.10", report.HostUnreachable[0].Host)
	require.Empty(t, report.HostChanged, "no per-port diff outside the host-level group")
	require.Equal(t, GroupHostUnreachable, report.HostUnreachable[0].Group)
	require.Len(t, report.HostUnreachable[0].Changes, 1)
	require.Equal(t, CategoryHostDown, report.HostUnreachable[0].Changes[0].Category)
	require.Equal(t, 1, report.Summary[CategoryHostDown])
	require.Equal(t, 0, report.Summary[CategoryClosed],
		"a host that went away must not be reported as ports closed")
}

// 形态 6：上一轮不可达、这一轮恢复 — 整体归主机恢复，不逐端口报新开。
func TestCompareHostRecovered(t *testing.T) {
	scope := fullScope(80, 443)
	previous := NewSnapshot(scope)
	previous.AddHost("192.0.2.10", HostUnreachable)

	current := NewSnapshot(scope)
	current.AddHost("192.0.2.10", HostReachable)
	current.AddPort(tcpPort("192.0.2.10", 80, nil))
	current.AddPort(tcpPort("192.0.2.10", 443, nil))

	report, err := Compare(previous, current)
	require.NoError(t, err)

	require.Len(t, report.HostRecovered, 1)
	require.Len(t, report.HostRecovered[0].Changes, 2)
	for _, change := range report.HostRecovered[0].Changes {
		require.Equal(t, CategoryUncertainResolved, change.Category)
	}
	require.Equal(t, 0, report.Summary[CategoryNew])
}

// 形态 5：目标集合扩大 — 新主机单独成组，不混进已有主机的差异。
func TestCompareNewTargetGroupedSeparately(t *testing.T) {
	scope := fullScope(80)
	previous := NewSnapshot(scope)
	previous.AddHost("192.0.2.10", HostReachable)
	previous.AddPort(tcpPort("192.0.2.10", 80, nil))

	current := NewSnapshot(scope)
	current.AddHost("192.0.2.10", HostReachable)
	current.AddPort(tcpPort("192.0.2.10", 80, nil))
	current.AddHost("192.0.2.99", HostReachable)
	current.AddPort(tcpPort("192.0.2.99", 80, nil))

	report, err := Compare(previous, current)
	require.NoError(t, err)

	require.Len(t, report.NewTargets, 1)
	require.Equal(t, "192.0.2.99", report.NewTargets[0].Host)
	for _, group := range report.HostChanged {
		for _, change := range group.Changes {
			require.NotEqual(t, CategoryNew, change.Category,
				"new-target ports must not leak into existing-host new ports")
		}
	}
	require.Len(t, report.HostChanged, 1)
	require.Equal(t, CategoryUnchanged, report.HostChanged[0].Changes[0].Category)
	require.Len(t, report.NewTargets[0].Changes, 1)
	require.Equal(t, CategoryNew, report.NewTargets[0].Changes[0].Category)
}

// 目标集合扩大也可以通过 targets 覆盖集识别：当前轮新增网段里的主机即使没有
// 显式 host 记录，也单独成组，不混进已有主机。
func TestCompareNewTargetFromCoverage(t *testing.T) {
	scope := fullScope(80)
	previous := NewSnapshot(scope)
	previous.AddTarget("10.0.0.0/24")
	previous.AddTarget("10.0.1.0/24")
	previous.AddHost("10.0.1.5", HostReachable)
	previous.AddPort(tcpPort("10.0.1.5", 80, nil))

	current := NewSnapshot(scope)
	current.AddTarget("10.0.0.0/24")
	current.AddTarget("10.0.1.0/24")
	current.AddTarget("10.0.2.0/24")
	current.AddHost("10.0.1.5", HostReachable)
	current.AddPort(tcpPort("10.0.1.5", 80, nil))
	current.AddHost("10.0.2.7", HostReachable)
	current.AddPort(tcpPort("10.0.2.7", 80, nil))

	report, err := Compare(previous, current)
	require.NoError(t, err)

	require.Len(t, report.NewTargets, 1)
	require.Equal(t, "10.0.2.7", report.NewTargets[0].Host)
	require.Equal(t, CategoryNew, report.NewTargets[0].Changes[0].Category)
}

// 形态 1：三类合起来等于本轮全量（对一个两轮都在的主机）。
func TestComparePartitionsCoverCurrentInventory(t *testing.T) {
	scope := fullScope(80, 81, 82, 83)
	previous := NewSnapshot(scope)
	previous.AddHost("h", HostReachable)
	previous.AddPort(tcpPort("h", 80, nil))           // unchanged
	previous.AddPort(tcpPort("h", 81, httpService())) // fingerprint changes
	previous.AddPort(tcpPort("h", 82, nil))           // closes

	current := NewSnapshot(scope)
	current.AddHost("h", HostReachable)
	current.AddPort(tcpPort("h", 80, nil))
	current.AddPort(tcpPort("h", 81, &ServiceFingerprint{Name: "http", Product: "apache"}))
	current.AddPort(tcpPort("h", 83, nil)) // new

	report, err := Compare(previous, current)
	require.NoError(t, err)

	require.Len(t, report.HostChanged, 1)
	changes := report.HostChanged[0].Changes
	categories := map[string]int{}
	for _, change := range changes {
		categories[change.Category]++
	}
	require.Equal(t, 1, categories[CategoryUnchanged])
	require.Equal(t, 1, categories[CategoryFingerprintChanged])
	require.Equal(t, 1, categories[CategoryNew])
	require.Equal(t, 1, categories[CategoryClosed])

	currentOpen := categories[CategoryNew] + categories[CategoryUnchanged] + categories[CategoryFingerprintChanged]
	require.Equal(t, 3, currentOpen, "new+unchanged+fingerprint must equal the current open count")
}

// 验收 2：端口范围不一致时，未扫描端口不能算成关闭。
func TestScopeMismatchNeverTreatsUnscannedAsClosed(t *testing.T) {
	// 上一轮扫 80,8080；这一轮只扫 80。8080 这一轮根本没探。
	previous := NewSnapshot(fullScope(80, 8080))
	previous.AddHost("h", HostReachable)
	previous.AddPort(tcpPort("h", 80, nil))
	previous.AddPort(tcpPort("h", 8080, nil))

	current := NewSnapshot(fullScope(80))
	current.AddHost("h", HostReachable)
	current.AddPort(tcpPort("h", 80, nil))

	report, err := Compare(previous, current)
	require.NoError(t, err)

	require.True(t, report.ScopeMismatch)
	require.Contains(t, report.ScopeWarning, "port scope differs")
	require.ElementsMatch(t, []string{ScopeKey("tcp", 8080)}, report.PreviousOnlyScope)
	for _, group := range report.HostChanged {
		for _, change := range group.Changes {
			require.NotEqual(t, CategoryClosed, change.Category,
				"a port outside the current scan scope must not be reported closed")
		}
	}
	require.Equal(t, 0, report.Summary[CategoryClosed])
}

// 反向：这一轮新扩的范围里探到的端口，是范围新增而非主机新开。
func TestScopeMismatchWidenedScopeNotNew(t *testing.T) {
	previous := NewSnapshot(fullScope(80))
	previous.AddHost("h", HostReachable)
	previous.AddPort(tcpPort("h", 80, nil))

	current := NewSnapshot(fullScope(80, 8080))
	current.AddHost("h", HostReachable)
	current.AddPort(tcpPort("h", 80, nil))
	current.AddPort(tcpPort("h", 8080, nil))

	report, err := Compare(previous, current)
	require.NoError(t, err)
	require.True(t, report.ScopeMismatch)
	require.Equal(t, 0, report.Summary[CategoryNew],
		"the previous round never probed 8080, so it cannot be called a new opening")
	// 本轮开放 80、8080 里，只有共享范围内的 80 参与三类归类（unchanged）；
	// 8080 通过 current_only_scope 呈现。
	require.Equal(t, 1, report.Summary[CategoryUnchanged])
	require.ElementsMatch(t, []string{ScopeKey("tcp", 8080)}, report.CurrentOnlyScope)
}

// 验收 3：同一对快照比对两次，结论逐字节相同。
func TestCompareIsDeterministic(t *testing.T) {
	scope := fullScope(80, 81, 82, 83)
	previous := NewSnapshot(scope)
	previous.AddHost("b", HostReachable)
	previous.AddHost("a", HostUnknown)
	previous.AddPort(tcpPort("b", 81, httpService()))
	previous.AddPort(tcpPort("a", 80, nil))

	current := NewSnapshot(scope)
	current.AddHost("b", HostReachable)
	current.AddHost("a", HostReachable)
	current.AddPort(tcpPort("b", 81, &ServiceFingerprint{Name: "http", Product: "apache"}))
	current.AddPort(tcpPort("b", 82, nil))
	current.AddPort(tcpPort("a", 80, nil))
	current.AddPort(tcpPort("a", 83, nil))

	first, err := Compare(previous, current)
	require.NoError(t, err)
	second, err := Compare(previous, current)
	require.NoError(t, err)

	firstBytes, err := first.MarshalCanonical()
	require.NoError(t, err)
	secondBytes, err := second.MarshalCanonical()
	require.NoError(t, err)
	require.Equal(t, string(firstBytes), string(secondBytes))

	var buf1, buf2 bytes.Buffer
	require.NoError(t, EncodeReport(&buf1, first))
	require.NoError(t, EncodeReport(&buf2, second))
	require.Equal(t, buf1.String(), buf2.String())
}

// 异输入但等价（主机/协议大小写、IPv4-mapped 写法）也必须归结到同一身份。
func TestCompareCanonicalIdentity(t *testing.T) {
	previous := NewSnapshot(fullScope(80))
	previous.AddHost("Example.COM.", HostReachable)
	previous.AddPort(PortEntry{Host: "::ffff:10.0.0.5", Port: 80, Protocol: "TCP"})

	current := NewSnapshot(fullScope(80))
	current.AddHost("example.com", HostReachable)
	current.AddPort(PortEntry{Host: "10.0.0.5", Port: 80, Protocol: "tcp"})

	report, err := Compare(previous, current)
	require.NoError(t, err)
	require.Equal(t, 1, report.Summary[CategoryUnchanged])
	require.Equal(t, 0, report.Summary[CategoryNew])
	require.Equal(t, 0, report.Summary[CategoryClosed])
}

// 异常 1：上一轮快照缺失 — 明确报错，绝不静默当作全部新开。
func TestReadMissingSnapshotErrors(t *testing.T) {
	_, err := ReadSnapshot(filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "previous snapshot")
}

// 异常 1：快照损坏 — 明确报错指出文件。
func TestReadCorruptSnapshotErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0600))
	_, err := ReadSnapshot(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "previous snapshot")
}

// 格式版本不被支持时拒绝读取，而不是按错误布局解释。
func TestReadUnsupportedVersionErrors(t *testing.T) {
	var raw bytes.Buffer
	snap := NewSnapshot(fullScope(80))
	snap.FormatVersion = 999
	require.NoError(t, json.NewEncoder(&raw).Encode(snap))
	_, err := DecodeSnapshot(&raw)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported snapshot format version")
}

// 异常 3：比对/写报告中途失败不留半截文件 — 原子写保证旧文件保持不变。
func TestWriteReportIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	original := []byte("previous round content\n")
	require.NoError(t, os.WriteFile(path, original, 0600))

	report, err := Compare(NewSnapshot(fullScope(80)), NewSnapshot(fullScope(80)))
	require.NoError(t, err)
	require.NoError(t, WriteReport(path, report))

	// File replaced wholesale, no temp files left behind.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEqual(t, original, data)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, strings.HasPrefix(entry.Name(), ".naabu-diff-"), "temp file leaked")
	}
	require.True(t, json.Valid(data))
}

// 快照写盘后可无损读回，且排序后逐字节稳定（硬约束 3）。
func TestSnapshotRoundTripAndStableBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")

	build := func() *Snapshot {
		snap := NewSnapshot(fullScope(81, 80))
		snap.AddHost("h2", HostReachable)
		snap.AddHost("h1", HostUnknown)
		snap.AddPort(tcpPort("h2", 80, httpService()))
		snap.AddPort(tcpPort("h2", 81, nil))
		return snap
	}

	require.NoError(t, WriteSnapshot(path, build()))
	first, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, WriteSnapshot(path, build()))
	second, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(first), string(second))

	loaded, err := ReadSnapshot(path)
	require.NoError(t, err)
	require.Equal(t, SnapshotFormatVersion, loaded.FormatVersion)
	require.Equal(t, []string{ScopeKey("tcp", 80), ScopeKey("tcp", 81)}, loaded.PortScope)
}

// 身份键不含时间/源/顺序，只含主机、协议、端口（硬约束 1）。
func TestEntryKeyIsStable(t *testing.T) {
	require.Equal(t,
		EntryKey("10.0.0.1", 8080, "tcp"),
		EntryKey("10.0.0.1", 8080, "tcp"))
	require.NotEqual(t,
		EntryKey("10.0.0.1", 8080, "tcp"),
		EntryKey("10.0.0.1", 8080, "udp"))
	require.NotEqual(t,
		EntryKey("10.0.0.1", 8080, "tcp"),
		EntryKey("10.0.0.2", 8080, "tcp"))
	require.Equal(t, "10.0.0.1|tcp/8080", EntryKey("10.0.0.1", 8080, "tcp"))
}

// 流式解码入口能处理一条 JSON 快照（硬约束 5 的解码侧）。
func TestDecodeSnapshotFromStream(t *testing.T) {
	snap := NewSnapshot(fullScope(80))
	snap.AddHost("h", HostReachable)
	snap.AddPort(tcpPort("h", 80, nil))
	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(snap))

	loaded, err := DecodeSnapshot(&buf)
	require.NoError(t, err)
	require.Len(t, loaded.Ports, 1)
	require.Equal(t, HostReachable, loaded.Hosts[0].Status)
}

// Compare 的 nil 输入显式失败，不产生空报告。
func TestCompareNilInputs(t *testing.T) {
	_, err := Compare(nil, NewSnapshot(nil))
	require.Error(t, err)
	_, err = Compare(NewSnapshot(nil), nil)
	require.Error(t, err)
}

// 目标覆盖集：大网段不必展开，靠前缀判定；排除项优先。
func TestCoveragePrefixLookup(t *testing.T) {
	previous := NewSnapshot(fullScope(80))
	previous.AddTarget("10.1.0.0/16")
	previous.Excluded = []string{"10.1.9.0/24"}
	previous.AddHost("10.1.1.1", HostReachable)
	previous.AddPort(tcpPort("10.1.1.1", 80, nil))

	current := NewSnapshot(fullScope(80))
	current.AddTarget("10.1.0.0/16")
	current.AddTarget("10.20.0.0/16")
	current.Excluded = []string{"10.1.9.0/24"}
	current.AddHost("10.1.1.1", HostReachable)
	current.AddPort(tcpPort("10.1.1.1", 80, nil))
	// 10.20.x.x 不在上一轮目标里：单独成组。
	current.AddHost("10.20.1.1", HostReachable)
	current.AddPort(tcpPort("10.20.1.1", 80, nil))

	report, err := Compare(previous, current)
	require.NoError(t, err)
	require.Len(t, report.NewTargets, 1)
	require.Equal(t, "10.20.1.1", report.NewTargets[0].Host)
}

// 覆盖率判定顺序：排除优先于包含。
func TestCoverageExclusionWinsOverInclusion(t *testing.T) {
	c := newCoverage([]string{"10.0.0.0/8", "192.168.1.5"}, []string{"10.1.0.0/16"})
	require.True(t, c.contains("10.2.3.4"))
	require.False(t, c.contains("10.1.3.4"))
	require.True(t, c.contains("192.168.1.5"))
	require.False(t, c.contains("192.168.1.6"))
}

// 上一轮标记为 partial 时，覆盖率内但没有显式状态的主机只能算 unknown：
// 不能把没探完的主机当作"确认无开放端口"。
func TestPartialRoundMarksCoveredHostsUnknown(t *testing.T) {
	previous := NewSnapshot(fullScope(80))
	previous.Partial = true
	previous.AddHost("10.0.0.1", HostReachable)
	previous.AddPort(tcpPort("10.0.0.1", 80, nil))

	current := NewSnapshot(fullScope(80))
	current.AddHost("10.0.0.1", HostReachable)
	current.AddPort(tcpPort("10.0.0.1", 80, nil))

	previous.Targets = []string{"10.0.0.1", "10.0.0.2"}
	current.Targets = []string{"10.0.0.1", "10.0.0.2"}

	report, err := Compare(previous, current)
	require.NoError(t, err)
	// 10.0.0.2 上一轮未探完、这一轮没有开放端口：不能当作确认关闭。
	for _, group := range report.HostChanged {
		for _, change := range group.Changes {
			require.NotEqual(t, CategoryClosed, change.Category)
		}
	}
	require.Equal(t, 0, report.Summary[CategoryClosed])
}

// 上一轮部分主机的端口这一轮没出现，属于不确定性丢弃，不是关闭。
func TestUnknownHostMissingPortIsUncertainDropped(t *testing.T) {
	previous := NewSnapshot(fullScope(80, 8080))
	previous.AddHost("h", HostUnknown)
	previous.AddPort(tcpPort("h", 80, nil))

	current := NewSnapshot(fullScope(80, 8080))
	current.AddHost("h", HostReachable)

	report, err := Compare(previous, current)
	require.NoError(t, err)
	change := findChange(t, report.HostChanged, "h", 80, "tcp")
	require.Equal(t, CategoryUncertainDropped, change.Category)
	require.Equal(t, 0, report.Summary[CategoryClosed])
}

// 硬约束 5：十万级端口条目能完成比对，且只随开放条目数量线性增长（不会按
// 主机 x 端口展开）。
func TestCompareHandlesHundredThousandEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("large snapshot test")
	}
	const hosts = 1000
	const portsPerHost = 100
	const portBase = 1000

	scope := make([]string, 0, portsPerHost)
	for p := 0; p < portsPerHost; p++ {
		scope = append(scope, ScopeKey("tcp", portBase+p))
	}

	previous := NewSnapshot(scope)
	current := NewSnapshot(scope)
	for h := 0; h < hosts; h++ {
		host := "10.42." + strconv.Itoa(h/256%256) + "." + strconv.Itoa(h%256)
		previous.AddHost(host, HostReachable)
		current.AddHost(host, HostReachable)
		for p := 0; p < portsPerHost; p++ {
			portNum := portBase + p
			previous.AddPort(tcpPort(host, portNum, nil))
			switch {
			case p%10 == 0: // 10% close
			case p%10 == 1: // 10% fingerprint shift
				current.AddPort(tcpPort(host, portNum, &ServiceFingerprint{Version: "2"}))
			default:
				current.AddPort(tcpPort(host, portNum, nil))
			}
		}
	}

	report, err := Compare(previous, current)
	require.NoError(t, err)
	require.Equal(t, hosts*portsPerHost/10, report.Summary[CategoryClosed])
	require.Equal(t, hosts*portsPerHost/10, report.Summary[CategoryFingerprintChanged])
	require.Equal(t, hosts*portsPerHost*8/10, report.Summary[CategoryUnchanged])

	// Canonical serialization must stay byte-stable at this size too.
	first, err := report.MarshalCanonical()
	require.NoError(t, err)
	second, err := report.MarshalCanonical()
	require.NoError(t, err)
	require.Equal(t, first, second)
}
