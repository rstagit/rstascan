package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	Version        = "1.0.0"
	DefaultPort    = 443
	DefaultTimeout = 4 * time.Second
	MaxWorkers     = 64
	MinWorkers     = 1
)

var colorEnabled bool

func init() {
	rand.Seed(time.Now().UnixNano())
	if os.Getenv("NO_COLOR") != "" {
		return
	}
	fi, err := os.Stdout.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		colorEnabled = true
	}
}

func col(code, t string) string {
	if colorEnabled {
		return "\033[" + code + "m" + t + "\033[0m"
	}
	return t
}

func green(t string) string   { return col("92", t) }
func red(t string) string     { return col("91", t) }
func yellow(t string) string  { return col("93", t) }
func cyan(t string) string    { return col("96", t) }
func blue(t string) string    { return col("94", t) }
func magenta(t string) string { return col("95", t) }
func bold(t string) string    { return col("1", t) }
func dim(t string) string     { return col("2", t) }
func white(t string) string   { return col("97", t) }

const banner = `
 ██████╗ ███████╗████████╗ █████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██████╔╝███████╗   ██║   ███████║    ███████╗██║     ███████║██╔██╗ ██║
 ██╔══██╗╚════██║   ██║   ██╔══██║    ╚════██║██║     ██╔══██║██║╚██╗██║
 ██║  ██║███████║   ██║   ██║  ██║    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
`

type ScanResult struct {
	IP        string
	SNI       string
	Port      int
	Latency   time.Duration
	TLSHello  bool
	ServerAck bool
	Status    string
	Error     string
	Timestamp time.Time
}

func (r *ScanResult) IsAlive() bool {
	return r.ServerAck || r.TLSHello
}

type HelloBuilder struct{}

var (
	cipherSuites, _ = hex.DecodeString(
		"0024" +
			"1302" + "1303" + "1301" + "c02c" + "c030" + "c02b" + "c02f" +
			"cca9" + "cca8" + "c024" + "c028" + "c023" + "c027" +
			"009f" + "009e" + "006b" + "0067" + "00ff")
	supportedGroups, _ = hex.DecodeString(
		"000a" + "0016" + "0014" +
			"001d" + "0017" + "001e" + "0019" + "0018" +
			"0100" + "0101" + "0102" + "0103" + "0104")
	signatureAlgorithms, _ = hex.DecodeString(
		"000d" + "002a" + "0028" +
			"0403" + "0503" + "0603" + "0807" + "0808" + "0809" + "080a" + "080b" +
			"0804" + "0805" + "0806" + "0401" + "0501" + "0601" +
			"0303" + "0301" + "0302" + "0402" + "0502" + "0602")
	ecPointFormats, _       = hex.DecodeString("000b" + "0004" + "0300" + "0102")
	sessionTicket, _        = hex.DecodeString("0023" + "0000")
	alpn, _                 = hex.DecodeString("0010" + "000e" + "000c" + "0268" + "3208" + "6874" + "7470" + "2f31" + "2e31")
	encryptThenMAC, _       = hex.DecodeString("0016" + "0000")
	extendedMasterSecret, _ = hex.DecodeString("0017" + "0000")
	supportedVersions, _    = hex.DecodeString("002b" + "0005" + "04" + "0304" + "0303")
	pskKeyExchange, _        = hex.DecodeString("002d" + "0002" + "0101")
)

func concat(slices ...[]byte) []byte {
	total := 0
	for _, s := range slices {
		total += len(s)
	}
	out := make([]byte, 0, total)
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}

func (HelloBuilder) BuildSNIExtension(sni string) []byte {
	sb := []byte(sni)
	entry := make([]byte, 3+len(sb))
	entry[0] = 0
	binary.BigEndian.PutUint16(entry[1:], uint16(len(sb)))
	copy(entry[3:], sb)
	nameList := make([]byte, 2+len(entry))
	binary.BigEndian.PutUint16(nameList, uint16(len(entry)))
	copy(nameList[2:], entry)
	result := make([]byte, 4+len(nameList))
	binary.BigEndian.PutUint16(result, 0x0000)
	binary.BigEndian.PutUint16(result[2:], uint16(len(nameList)))
	copy(result[4:], nameList)
	return result
}

func (HelloBuilder) BuildKeyShare() []byte {
	pub := make([]byte, 32)
	rand.Read(pub)
	entry := make([]byte, 4+len(pub))
	binary.BigEndian.PutUint16(entry, 0x001D)
	binary.BigEndian.PutUint16(entry[2:], 32)
	copy(entry[4:], pub)
	data := make([]byte, 2+len(entry))
	binary.BigEndian.PutUint16(data, uint16(len(entry)))
	copy(data[2:], entry)
	result := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(result, 0x0033)
	binary.BigEndian.PutUint16(result[2:], uint16(len(data)))
	copy(result[4:], data)
	return result
}

func (b HelloBuilder) Build(sni string) []byte {
	sessionID := make([]byte, 32)
	randomBytes := make([]byte, 32)
	rand.Read(sessionID)
	rand.Read(randomBytes)

	clientVersion := []byte{0x03, 0x03}
	sessionIDField := append([]byte{byte(len(sessionID))}, sessionID...)
	compression := []byte{0x01, 0x00}
	sniExt := b.BuildSNIExtension(sni)
	keyShareExt := b.BuildKeyShare()

	extensions := concat(sniExt, ecPointFormats, supportedGroups,
		sessionTicket, alpn, encryptThenMAC,
		extendedMasterSecret, signatureAlgorithms,
		supportedVersions, pskKeyExchange, keyShareExt)

	extWithLen := make([]byte, 2+len(extensions))
	binary.BigEndian.PutUint16(extWithLen, uint16(len(extensions)))
	copy(extWithLen[2:], extensions)

	handshakeBody := concat(clientVersion, randomBytes, sessionIDField, cipherSuites, compression, extWithLen)

	hsLen := len(handshakeBody)
	handshake := make([]byte, 4+hsLen)
	handshake[0] = 0x01
	handshake[1] = byte(hsLen >> 16)
	handshake[2] = byte(hsLen >> 8)
	handshake[3] = byte(hsLen)
	copy(handshake[4:], handshakeBody)

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:], uint16(len(handshake)))
	copy(record[5:], handshake)
	return record
}

type Target struct {
	IP   string
	SNI  string
	Port int
}

type Scanner struct {
	timeout    time.Duration
	workers    int
	port       int
	results    []ScanResult
	mu         sync.Mutex
	done       int64
	total      int64
	alive      int64
	failed     int64
	startTime  time.Time
}

func NewScanner(timeout time.Duration, workers, port int) *Scanner {
	return &Scanner{
		timeout: timeout,
		workers: workers,
		port:    port,
	}
}

func (s *Scanner) probeTarget(t Target) ScanResult {
	result := ScanResult{
		IP:        t.IP,
		SNI:       t.SNI,
		Port:      t.Port,
		Timestamp: time.Now(),
	}

	addr := fmt.Sprintf("%s:%d", t.IP, t.Port)
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, s.timeout)
	if err != nil {
		result.Status = "unreachable"
		result.Error = simplifyErr(err)
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(s.timeout))

	sni := t.SNI
	if sni == "" {
		sni = t.IP
	}

	b := HelloBuilder{}
	hello := b.Build(sni)

	_, err = conn.Write(hello)
	if err != nil {
		result.Status = "write_fail"
		result.Error = simplifyErr(err)
		return result
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)

	result.Latency = time.Since(start)

	if n > 0 {
		result.ServerAck = true
		if n >= 3 && buf[0] == 0x16 {
			result.TLSHello = true
			result.Status = "tls_ok"
		} else if n >= 3 && buf[0] == 0x15 {
			result.TLSHello = true
			result.Status = "tls_alert"
		} else {
			result.Status = "tcp_ok"
		}
	} else if err != nil {
		result.Status = "timeout"
		result.Error = "no response"
	} else {
		result.Status = "empty"
	}

	return result
}

func simplifyErr(err error) string {
	s := err.Error()
	if strings.Contains(s, "refused") {
		return "connection refused"
	}
	if strings.Contains(s, "timeout") || strings.Contains(s, "deadline") {
		return "timeout"
	}
	if strings.Contains(s, "no route") {
		return "no route"
	}
	if strings.Contains(s, "network unreachable") {
		return "unreachable"
	}
	return s
}

func (s *Scanner) Run(targets []Target, live bool) []ScanResult {
	s.total = int64(len(targets))
	s.done = 0
	s.alive = 0
	s.failed = 0
	s.startTime = time.Now()
	s.results = nil

	jobs := make(chan Target, len(targets))
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				r := s.probeTarget(t)
				atomic.AddInt64(&s.done, 1)
				if r.IsAlive() {
					atomic.AddInt64(&s.alive, 1)
				} else {
					atomic.AddInt64(&s.failed, 1)
				}
				s.mu.Lock()
				s.results = append(s.results, r)
				s.mu.Unlock()
				if live {
					printLiveResult(r)
				}
			}
		}()
	}

	if !live {
		go s.progressLoop()
	}

	wg.Wait()
	return s.results
}

func (s *Scanner) progressLoop() {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		d := atomic.LoadInt64(&s.done)
		t := atomic.LoadInt64(&s.total)
		a := atomic.LoadInt64(&s.alive)
		if d >= t {
			s.printProgress(d, t, a)
			fmt.Println()
			return
		}
		s.printProgress(d, t, a)
		<-ticker.C
	}
}

func (s *Scanner) printProgress(done, total, alive int64) {
	elapsed := time.Since(s.startTime).Seconds()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(done) / elapsed
	}
	pct := 0
	if total > 0 {
		pct = int(done * 100 / total)
	}
	barW := 30
	filled := barW * pct / 100
	bar := green(strings.Repeat("█", filled)) + dim(strings.Repeat("░", barW-filled))
	fmt.Printf("\r  %s %s%s%s  %s/%s  %s alive  %.0f/s   ",
		dim("Progress:"),
		dim("["), bar, dim("]"),
		cyan(fmt.Sprintf("%d", done)),
		white(fmt.Sprintf("%d", total)),
		green(fmt.Sprintf("%d", alive)),
		rate,
	)
}

func printLiveResult(r ScanResult) {
	ts := time.Now().Format("15:04:05")
	latStr := ""
	if r.Latency > 0 {
		latStr = fmt.Sprintf(" %s", dim(fmt.Sprintf("%.0fms", float64(r.Latency.Milliseconds()))))
	}
	sniStr := ""
	if r.SNI != "" && r.SNI != r.IP {
		sniStr = dim(" sni=") + cyan(r.SNI)
	}

	switch {
	case r.TLSHello && r.Status == "tls_ok":
		fmt.Printf("  %s %s %s%s%s\n",
			dim(ts), green("✓ TLS  "), bold(r.IP), latStr, sniStr)
	case r.TLSHello && r.Status == "tls_alert":
		fmt.Printf("  %s %s %s%s%s\n",
			dim(ts), yellow("~ ALERT"), bold(r.IP), latStr, sniStr)
	case r.ServerAck:
		fmt.Printf("  %s %s %s%s%s\n",
			dim(ts), cyan("◎ TCP  "), bold(r.IP), latStr, sniStr)
	default:
		fmt.Printf("  %s %s %s  %s\n",
			dim(ts), red("✗ DEAD "), dim(r.IP), dim(r.Error))
	}
}

func printResults(results []ScanResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].IsAlive() != results[j].IsAlive() {
			return results[i].IsAlive()
		}
		return results[i].Latency < results[j].Latency
	})

	alive := 0
	for _, r := range results {
		if r.IsAlive() {
			alive++
		}
	}

	fmt.Printf("\n  %s\n", bold(strings.Repeat("─", 60)))
	fmt.Printf("  %s  %s alive out of %s total\n\n",
		bold("Results:"),
		green(fmt.Sprintf("%d", alive)),
		white(fmt.Sprintf("%d", len(results))))

	for _, r := range results {
		latStr := ""
		if r.Latency > 0 {
			lat := float64(r.Latency.Milliseconds())
			latColor := green
			if lat > 300 {
				latColor = yellow
			}
			if lat > 800 {
				latColor = red
			}
			latStr = fmt.Sprintf("  %s", latColor(fmt.Sprintf("%.0fms", lat)))
		}

		sniStr := ""
		if r.SNI != "" && r.SNI != r.IP {
			sniStr = dim("  sni=") + cyan(r.SNI)
		}

		switch {
		case r.TLSHello && r.Status == "tls_ok":
			fmt.Printf("  %s  %-18s%s%s\n",
				green("✓ TLS  "), bold(fmt.Sprintf("%s:%d", r.IP, r.Port)), latStr, sniStr)
		case r.TLSHello && r.Status == "tls_alert":
			fmt.Printf("  %s  %-18s%s%s\n",
				yellow("~ ALERT"), bold(fmt.Sprintf("%s:%d", r.IP, r.Port)), latStr, sniStr)
		case r.ServerAck:
			fmt.Printf("  %s  %-18s%s%s\n",
				cyan("◎ TCP  "), bold(fmt.Sprintf("%s:%d", r.IP, r.Port)), latStr, sniStr)
		default:
			fmt.Printf("  %s  %-18s  %s\n",
				red("✗ DEAD "), dim(fmt.Sprintf("%s:%d", r.IP, r.Port)), dim(r.Error))
		}
	}
	fmt.Printf("\n  %s\n", dim(strings.Repeat("─", 60)))
}

func resolveToIP(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	for _, a := range addrs {
		if net.ParseIP(a).To4() != nil {
			return a
		}
	}
	return addrs[0]
}

func pingResolve(host string, timeout time.Duration) string {
	if ip := resolveToIP(host); ip != "" {
		return ip
	}
	conn, err := net.DialTimeout("tcp", host+":80", timeout)
	if err == nil {
		conn.Close()
		h, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		return h
	}
	return ""
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := cloneIP(ipNet.IP.Mask(ipNet.Mask)); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func expandRange(rangeStr string) ([]string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format, expected x.x.x.x-x.x.x.x")
	}
	startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IPs in range")
	}
	start := binary.BigEndian.Uint32(startIP)
	end := binary.BigEndian.Uint32(endIP)
	if start > end {
		return nil, fmt.Errorf("start IP must be <= end IP")
	}
	var ips []string
	for i := start; i <= end; i++ {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, i)
		ips = append(ips, net.IP(b).String())
	}
	return ips, nil
}

func parseTXTLine(line string) (ip, sni string, port int, err error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", 0, fmt.Errorf("skip")
	}
	port = DefaultPort
	fields := strings.Fields(line)

	if len(fields) == 1 {
		val := fields[0]
		if strings.Contains(val, ",") {
			parts := strings.SplitN(val, ",", 3)
			ip = strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				sni = strings.TrimSpace(parts[1])
			}
			if len(parts) > 2 {
				if p, e := strconv.Atoi(strings.TrimSpace(parts[2])); e == nil {
					port = p
				}
			}
		} else if strings.Contains(val, ":") {
			h, p, e := net.SplitHostPort(val)
			if e == nil {
				ip = h
				if pn, e2 := strconv.Atoi(p); e2 == nil {
					port = pn
				}
			} else {
				ip = val
			}
		} else {
			ip = val
		}
	} else if len(fields) >= 2 {
		ip = fields[0]
		sni = fields[1]
		if len(fields) >= 3 {
			if p, e := strconv.Atoi(fields[2]); e == nil {
				port = p
			}
		}
	}

	if ip == "" {
		return "", "", 0, fmt.Errorf("no IP found")
	}
	return ip, sni, port, nil
}

func loadTargetsFromFile(path string, defaultPort int) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []Target
	scanner := bufio.NewScanner(f)
	lineNum := 0
	skipped := 0
	for scanner.Scan() {
		lineNum++
		ip, sni, port, err := parseTXTLine(scanner.Text())
		if err != nil {
			skipped++
			continue
		}
		if port == DefaultPort {
			port = defaultPort
		}
		targets = append(targets, Target{IP: ip, SNI: sni, Port: port})
	}
	return targets, scanner.Err()
}

type Menu struct {
	scanner *Scanner
}

func NewMenu() *Menu {
	return &Menu{
		scanner: NewScanner(DefaultTimeout, 16, DefaultPort),
	}
}

func (m *Menu) printBanner() {
	if colorEnabled {
		fmt.Println(cyan(banner))
	} else {
		fmt.Println(banner)
	}
	w := 62
	fmt.Printf("  %s\n", dim(strings.Repeat("─", w)))
	fmt.Printf("  %s  v%s  —  SNI Connection Tester\n",
		bold("RSTA SCAN"), Version)
	fmt.Printf("  %s  %s\n",
		dim("Platform:"), white(runtime.GOOS+"/"+runtime.GOARCH))
	fmt.Printf("  %s  timeout=%.1fs  workers=%d  port=%d\n",
		dim("Defaults:"),
		m.scanner.timeout.Seconds(),
		m.scanner.workers,
		m.scanner.port)
	fmt.Printf("  %s\n\n", dim(strings.Repeat("─", w)))
}

func (m *Menu) printHelp() {
	items := [][]string{
		{"1", "Single scan", "scan one IP or hostname (with optional SNI)"},
		{"2", "File scan", "load targets from .txt file (multiple formats)"},
		{"3", "CIDR scan", "scan an IP range like 1.1.1.0/24"},
		{"4", "IP range scan", "scan from 1.1.1.1 to 1.1.1.50"},
		{"5", "IP range + SNI", "scan IP range and test each with a fixed SNI"},
		{"6", "Settings", "change timeout / workers / port"},
		{"0", "Exit", ""},
	}
	fmt.Printf("\n  %s\n", bold("Commands"))
	fmt.Printf("  %s\n", dim(strings.Repeat("─", 50)))
	for _, it := range items {
		num := cyan(it[0])
		cmd := bold(it[1])
		desc := dim(it[2])
		if it[2] == "" {
			fmt.Printf("  [%s]  %s\n", num, cmd)
		} else {
			fmt.Printf("  [%s]  %-20s %s\n", num, cmd, desc)
		}
	}
	fmt.Printf("  %s\n\n", dim(strings.Repeat("─", 50)))
}

func (m *Menu) prompt(label string) string {
	fmt.Printf("  %s %s", cyan("►"), label)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func (m *Menu) confirmScan(count int) bool {
	if count <= 10 {
		return true
	}
	fmt.Printf("\n  %s Scanning %s targets with %s workers. Continue? %s ",
		yellow("!"),
		yellow(fmt.Sprintf("%d", count)),
		white(fmt.Sprintf("%d", m.scanner.workers)),
		dim("[y/N]:"))
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes"
}

func (m *Menu) runScan(targets []Target, live bool) {
	if len(targets) == 0 {
		fmt.Printf("\n  %s No targets to scan.\n\n", yellow("!"))
		return
	}
	fmt.Printf("\n  %s Starting scan: %s targets\n",
		cyan("→"), bold(fmt.Sprintf("%d", len(targets))))
	if live {
		fmt.Printf("  %s\n\n", dim(strings.Repeat("─", 50)))
	}
	results := m.scanner.Run(targets, live)
	printResults(results)
}

func (m *Menu) singleScan() {
	fmt.Printf("\n  %s\n", bold("Single Target Scan"))
	fmt.Printf("  %s\n\n", dim("Leave SNI empty to test IP directly. Leave IP empty to resolve from SNI."))

	ipIn := m.prompt("IP address (or leave blank): ")
	sniIn := m.prompt("SNI hostname (or leave blank): ")
	portStr := m.prompt(fmt.Sprintf("Port [%d]: ", m.scanner.port))

	port := m.scanner.port
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}

	ip := strings.TrimSpace(ipIn)
	sni := strings.TrimSpace(sniIn)

	if ip == "" && sni == "" {
		fmt.Printf("\n  %s Please provide at least an IP or SNI.\n\n", red("✗"))
		return
	}

	if ip == "" && sni != "" {
		fmt.Printf("\n  %s Resolving %s ...\n", dim("→"), cyan(sni))
		resolved := resolveToIP(sni)
		if resolved == "" {
			fmt.Printf("  %s Could not resolve %s\n\n", red("✗"), sni)
			return
		}
		ip = resolved
		fmt.Printf("  %s Resolved to %s\n", green("✓"), green(ip))
	}

	target := Target{IP: ip, SNI: sni, Port: port}
	m.runScan([]Target{target}, true)
}

func (m *Menu) fileScan() {
	fmt.Printf("\n  %s\n", bold("File Scan"))
	fmt.Printf("  %s\n", dim("Supported formats per line:"))
	fmt.Printf("  %s\n", dim("  1.2.3.4"))
	fmt.Printf("  %s\n", dim("  1.2.3.4 example.com"))
	fmt.Printf("  %s\n", dim("  1.2.3.4,example.com,443"))
	fmt.Printf("  %s\n\n", dim("  1.2.3.4:443"))

	path := m.prompt("Path to .txt file: ")
	if path == "" {
		return
	}

	targets, err := loadTargetsFromFile(path, m.scanner.port)
	if err != nil {
		fmt.Printf("\n  %s Error: %v\n\n", red("✗"), err)
		return
	}
	fmt.Printf("\n  %s Loaded %s targets from file.\n",
		green("✓"), white(fmt.Sprintf("%d", len(targets))))

	if !m.confirmScan(len(targets)) {
		return
	}
	m.runScan(targets, len(targets) <= 50)
}

func (m *Menu) cidrScan() {
	fmt.Printf("\n  %s\n\n", bold("CIDR Range Scan"))
	cidrIn := m.prompt("CIDR (e.g. 1.1.1.0/24): ")
	sniIn := m.prompt("SNI for all targets (optional): ")
	portStr := m.prompt(fmt.Sprintf("Port [%d]: ", m.scanner.port))

	port := m.scanner.port
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}

	ips, err := expandCIDR(strings.TrimSpace(cidrIn))
	if err != nil {
		fmt.Printf("\n  %s %v\n\n", red("✗"), err)
		return
	}

	sni := strings.TrimSpace(sniIn)
	var targets []Target
	for _, ip := range ips {
		targets = append(targets, Target{IP: ip, SNI: sni, Port: port})
	}

	fmt.Printf("\n  %s Expanded %s to %s IPs.\n",
		green("✓"), cyan(cidrIn), white(fmt.Sprintf("%d", len(targets))))
	if !m.confirmScan(len(targets)) {
		return
	}
	m.runScan(targets, false)
}

func (m *Menu) ipRangeScan() {
	fmt.Printf("\n  %s\n\n", bold("IP Range Scan"))
	startIn := m.prompt("Start IP (e.g. 1.1.1.1): ")
	endIn := m.prompt("End IP   (e.g. 1.1.1.50): ")
	portStr := m.prompt(fmt.Sprintf("Port [%d]: ", m.scanner.port))

	port := m.scanner.port
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}

	rangeStr := strings.TrimSpace(startIn) + "-" + strings.TrimSpace(endIn)
	ips, err := expandRange(rangeStr)
	if err != nil {
		fmt.Printf("\n  %s %v\n\n", red("✗"), err)
		return
	}

	var targets []Target
	for _, ip := range ips {
		targets = append(targets, Target{IP: ip, SNI: "", Port: port})
	}

	fmt.Printf("\n  %s Range covers %s IPs.\n",
		green("✓"), white(fmt.Sprintf("%d", len(targets))))
	if !m.confirmScan(len(targets)) {
		return
	}
	m.runScan(targets, false)
}

func (m *Menu) ipRangeSNIScan() {
	fmt.Printf("\n  %s\n", bold("IP Range + SNI Scan"))
	fmt.Printf("  %s\n\n", dim("Tests each IP in the range with a real TLS ClientHello using your SNI."))

	startIn := m.prompt("Start IP (e.g. 1.1.1.1): ")
	endIn := m.prompt("End IP   (e.g. 1.1.1.50): ")
	sniIn := m.prompt("SNI hostname (required): ")
	portStr := m.prompt(fmt.Sprintf("Port [%d]: ", m.scanner.port))

	sni := strings.TrimSpace(sniIn)
	if sni == "" {
		fmt.Printf("\n  %s SNI is required for this mode.\n\n", red("✗"))
		return
	}

	port := m.scanner.port
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}

	rangeStr := strings.TrimSpace(startIn) + "-" + strings.TrimSpace(endIn)
	ips, err := expandRange(rangeStr)
	if err != nil {
		fmt.Printf("\n  %s %v\n\n", red("✗"), err)
		return
	}

	var targets []Target
	for _, ip := range ips {
		targets = append(targets, Target{IP: ip, SNI: sni, Port: port})
	}

	fmt.Printf("\n  %s %s IPs × SNI=%s\n",
		green("✓"), white(fmt.Sprintf("%d", len(targets))), cyan(sni))
	if !m.confirmScan(len(targets)) {
		return
	}
	m.runScan(targets, false)
}

func (m *Menu) settings() {
	fmt.Printf("\n  %s\n", bold("Settings"))
	fmt.Printf("  %s\n\n", dim(strings.Repeat("─", 40)))

	fmt.Printf("  Current: timeout=%s  workers=%s  port=%s\n\n",
		yellow(fmt.Sprintf("%.1fs", m.scanner.timeout.Seconds())),
		yellow(fmt.Sprintf("%d", m.scanner.workers)),
		yellow(fmt.Sprintf("%d", m.scanner.port)))

	tStr := m.prompt(fmt.Sprintf("Timeout in seconds [%.1f]: ", m.scanner.timeout.Seconds()))
	if tStr != "" {
		if v, err := strconv.ParseFloat(tStr, 64); err == nil && v > 0 {
			m.scanner.timeout = time.Duration(v * float64(time.Second))
		}
	}

	wStr := m.prompt(fmt.Sprintf("Workers [%d]: ", m.scanner.workers))
	if wStr != "" {
		if v, err := strconv.Atoi(wStr); err == nil && v >= MinWorkers && v <= MaxWorkers {
			m.scanner.workers = v
		} else if err == nil {
			fmt.Printf("  %s Workers must be between %d and %d\n", yellow("!"), MinWorkers, MaxWorkers)
		}
	}

	pStr := m.prompt(fmt.Sprintf("Default port [%d]: ", m.scanner.port))
	if pStr != "" {
		if v, err := strconv.Atoi(pStr); err == nil && v > 0 && v < 65536 {
			m.scanner.port = v
		}
	}

	fmt.Printf("\n  %s timeout=%.1fs  workers=%d  port=%d\n\n",
		green("✓ Settings updated:"),
		m.scanner.timeout.Seconds(),
		m.scanner.workers,
		m.scanner.port)
}

func (m *Menu) Run() {
	m.printBanner()
	m.printHelp()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Printf("\n\n  %s Bye.\n\n", dim("→"))
		os.Exit(0)
	}()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("  %s ", bold(magenta("rstascan >")))
		line, _ := reader.ReadString('\n')
		cmd := strings.TrimSpace(line)

		switch cmd {
		case "1":
			m.singleScan()
		case "2":
			m.fileScan()
		case "3":
			m.cidrScan()
		case "4":
			m.ipRangeScan()
		case "5":
			m.ipRangeSNIScan()
		case "6":
			m.settings()
		case "0", "exit", "quit", "q":
			fmt.Printf("\n  %s See you.\n\n", dim("→"))
			return
		case "help", "h", "?":
			m.printHelp()
		case "":
		default:
			fmt.Printf("\n  %s Unknown command. Type %s for help.\n\n",
				yellow("!"), cyan("help"))
		}
	}
}

func main() {
	menu := NewMenu()
	menu.Run()
}
