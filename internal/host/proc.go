package host

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// clockTicks is USER_HZ, which is 100 on every mainstream Linux architecture.
const clockTicks = 100

// Process is a snapshot of a running process from procfs.
type Process struct {
	PID     int
	PPID    int
	UID     int
	Comm    string
	Exe     string // readlink of /proc/PID/exe; may end in " (deleted)"
	Cmdline []string
	// CPUPercent is average CPU usage over the process lifetime.
	CPUPercent float64
	// Sockets holds socket inodes owned by the process.
	Sockets []uint64
}

// ExeDeleted reports whether the process image was deleted from disk.
func (p Process) ExeDeleted() bool { return strings.HasSuffix(p.Exe, " (deleted)") }

// ExePath returns the executable path without the " (deleted)" suffix.
func (p Process) ExePath() string { return strings.TrimSuffix(p.Exe, " (deleted)") }

// CommandLine returns the space-joined command line (or [comm] for kernel threads).
func (p Process) CommandLine() string {
	if len(p.Cmdline) == 0 {
		return "[" + p.Comm + "]"
	}
	return strings.Join(p.Cmdline, " ")
}

// Processes returns all processes visible in procfs. Results are cached for
// the life of the Host; unreadable per-process entries are skipped.
func (h *Host) Processes() ([]Process, error) {
	h.procOnce.Do(func() { h.procs, h.procErr = h.readProcesses() })
	return h.procs, h.procErr
}

func (h *Host) readProcesses() ([]Process, error) {
	entries, err := os.ReadDir(h.Proc)
	if err != nil {
		return nil, fmt.Errorf("read procfs %s: %w", h.Proc, err)
	}
	uptime := h.uptime()
	var out []Process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(h.Proc, e.Name())
		p := Process{PID: pid, UID: -1}
		if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
			p.Comm = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
			for a := range strings.SplitSeq(strings.TrimRight(string(b), "\x00"), "\x00") {
				if a != "" {
					p.Cmdline = append(p.Cmdline, a)
				}
			}
		}
		p.Exe, _ = os.Readlink(filepath.Join(dir, "exe"))
		if b, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
			p.UID = statusUID(string(b))
		}
		if b, err := os.ReadFile(filepath.Join(dir, "stat")); err == nil {
			p.PPID, p.CPUPercent = parseStat(string(b), uptime)
		}
		p.Sockets = socketInodes(filepath.Join(dir, "fd"))
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Process) int { return a.PID - b.PID })
	return out, nil
}

func (h *Host) uptime() float64 {
	b, err := os.ReadFile(h.ProcPath("uptime"))
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

func statusUID(s string) int {
	for l := range strings.SplitSeq(s, "\n") {
		if rest, ok := strings.CutPrefix(l, "Uid:"); ok {
			f := strings.Fields(rest)
			if len(f) > 0 {
				if v, err := strconv.Atoi(f[0]); err == nil {
					return v
				}
			}
		}
	}
	return -1
}

// parseStat extracts the parent PID and lifetime-average CPU percentage from
// /proc/PID/stat. The comm field may contain spaces and parentheses, so
// parsing starts after the last ')'.
func parseStat(s string, uptime float64) (ppid int, cpu float64) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, 0
	}
	f := strings.Fields(s[i+1:])
	// f[0] is field 3 (state); field N is f[N-3].
	if len(f) < 20 {
		return 0, 0
	}
	ppid, _ = strconv.Atoi(f[1])
	utime, _ := strconv.ParseFloat(f[11], 64)
	stime, _ := strconv.ParseFloat(f[12], 64)
	start, _ := strconv.ParseFloat(f[19], 64)
	elapsed := uptime - start/clockTicks
	if elapsed <= 0 {
		return ppid, 0
	}
	return ppid, (utime + stime) / clockTicks / elapsed * 100
}

func socketInodes(fdDir string) []uint64 {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	var out []uint64
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		if rest, ok := strings.CutPrefix(target, "socket:["); ok {
			if v, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64); err == nil {
				out = append(out, v)
			}
		}
	}
	return out
}

// Socket states from include/net/tcp_states.h.
const (
	StateEstablished = 0x01
	StateListen      = 0x0A
	// StateUnconnected is how an unconnected UDP socket appears (TCP_CLOSE).
	StateUnconnected = 0x07
)

// Socket is one row of /proc/net/{tcp,tcp6,udp,udp6}.
type Socket struct {
	Proto  string // tcp, tcp6, udp, udp6
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  int
	UID    int
	Inode  uint64
}

// Listening reports whether the socket accepts inbound traffic.
func (s Socket) Listening() bool {
	if strings.HasPrefix(s.Proto, "udp") {
		return s.State == StateUnconnected && s.Remote.Addr().IsUnspecified()
	}
	return s.State == StateListen
}

// Sockets parses the TCP and UDP socket tables of the host's network namespace.
func (h *Host) Sockets() ([]Socket, error) {
	var out []Socket
	found := false
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile(h.ProcPath("net/" + proto))
		if err != nil {
			continue
		}
		found = true
		socks, err := parseSocketTable(proto, string(b))
		if err != nil {
			return nil, fmt.Errorf("parse /proc/net/%s: %w", proto, err)
		}
		out = append(out, socks...)
	}
	if !found {
		return nil, fmt.Errorf("no socket tables under %s: %w", h.ProcPath("net"), os.ErrNotExist)
	}
	return out, nil
}

func parseSocketTable(proto, s string) ([]Socket, error) {
	var out []Socket
	for i, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 {
			continue
		}
		local, err := parseHexAddrPort(f[1])
		if err != nil {
			return nil, err
		}
		remote, err := parseHexAddrPort(f[2])
		if err != nil {
			return nil, err
		}
		state, err := strconv.ParseInt(f[3], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("state %q: %w", f[3], err)
		}
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Socket{Proto: proto, Local: local, Remote: remote, State: int(state), UID: uid, Inode: inode})
	}
	return out, nil
}

// parseHexAddrPort decodes the kernel's "0100007F:1F90" notation. Addresses
// are printed as host-endian 32-bit words; every Linux target hostwarden
// ships for (amd64, arm64) is little-endian.
func parseHexAddrPort(s string) (netip.AddrPort, error) {
	addrHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("malformed address %q", s)
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("malformed address %q", s)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("malformed port %q: %w", s, err)
	}
	for i := 0; i < len(raw); i += 4 {
		w := binary.LittleEndian.Uint32(raw[i:])
		binary.BigEndian.PutUint32(raw[i:], w)
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

// SocketOwners maps socket inodes to owning processes.
func (h *Host) SocketOwners() map[uint64]Process {
	procs, err := h.Processes()
	if err != nil {
		return nil
	}
	m := map[uint64]Process{}
	for _, p := range procs {
		for _, ino := range p.Sockets {
			if _, ok := m[ino]; !ok {
				m[ino] = p
			}
		}
	}
	return m
}

// MountEntry is one row of /proc/mounts.
type MountEntry struct {
	Device  string
	Point   string
	FSType  string
	Options []string
}

// HasOption reports whether the mount has the given option.
func (m MountEntry) HasOption(o string) bool { return slices.Contains(m.Options, o) }

// Mounts parses procfs mounts.
func (h *Host) Mounts() ([]MountEntry, error) {
	b, err := os.ReadFile(h.ProcPath("mounts"))
	if err != nil {
		return nil, err
	}
	var out []MountEntry
	for _, l := range splitLines(b) {
		f := strings.Fields(l.Text)
		if len(f) < 4 {
			continue
		}
		out = append(out, MountEntry{Device: f[0], Point: unescapeMount(f[1]), FSType: f[2], Options: strings.Split(f[3], ",")})
	}
	return out, nil
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
