package main

import "fmt"
import "flag"
import "bufio"
import "os"
import "log"
import "net"
import "sync"
import "time"
import "strings"
import "math/rand"
import "github.com/miekg/dns"
import "crypto/md5"
import "encoding/hex"

//flags
var resolverFile string
var nGoroutines int
var verbose bool
var debug bool
var dnsTimeout time.Duration
var nConcurrentJobs int
var minVerifications int

//globals
var famousResolvers = []string{"1.0.0.1", "1.1.1.1", "149.112.112.112", "176.103.130.130", "176.103.130.131", "185.228.168.9", "185.228.169.9", "198.101.242.72", "207.67.222.222", "208.67.220.220", "208.67.222.222", "23.253.163.53", "64.6.64.6", "64.6.65.6", "8.8.4.4", "8.8.8.8", "9.9.9.9"}

var inputDone = false

var jobs = map[string]bool{}
var jobsMutex = &sync.RWMutex{}

var wildcards = map[string]map[string]bool{}
var resolvers []net.IP
var dnsch chan string
var wg = sync.WaitGroup{}

var lookups = map[string]*DnsJob{}
var lookupsMutex = &sync.RWMutex{}

type DnsJob struct {
	sync.Mutex
	Name        string
	NLookups    int
	RequestTime time.Time
	Lookups     map[string]*dns.Msg
}

func main() {
	parseFlags()
	resolvers = getResolvers()
	dnsch = make(chan string, nGoroutines*nConcurrentJobs)
	startGoroutines(&wg)
	wg.Wait()
}

func startGoroutines(wg *sync.WaitGroup) {
	for i := 0; i < nGoroutines; i++ {
		c, err := net.ListenUDP("udp", nil)

		if err != nil {
			log.Panic(err)
		}

		wg.Add(2)
		go sender(dnsch, c, wg)
		go reciever(c, wg)
	}

	wg.Add(3)
	go retryer(wg)
	go worker(&jobs, wg)
	go loadJobs(&jobs, wg)
}

func loadJobs(jobs *map[string]bool, wg *sync.WaitGroup) {
	defer wg.Done()

	count := 0
	for scanner := bufio.NewScanner(os.Stdin); scanner.Scan(); count++ {
		for len(*jobs) > nConcurrentJobs {
			shortSleep()
		}
		line := strings.TrimSpace(scanner.Text())
		if _, ok := dns.IsDomainName(line); !ok {
			debugLog("Non valid domain name found:", line)
			continue
		}

		debugLog("Adds new domain job:", line)
		jobsMutex.Lock()
		(*jobs)[line] = true
		jobsMutex.Unlock()
	}
	debugLog("Number of input domains:", count)
	inputDone = true
}

func retryer(wg *sync.WaitGroup) {
	defer wg.Done()
	for hasWork() {
		debugLog("Starting retryer loop")
		shortSleep()
		lookupsMutex.RLock()
		for d, dnsJob := range lookups {
			if len(dnsJob.Lookups) == dnsJob.NLookups || dnsJob.RequestTime.Add(dnsTimeout).After(time.Now()) {
				continue
			}
			debugLog("Sending new requests:", d)
			for i := len(dnsJob.Lookups); i < dnsJob.NLookups; i++ {
				dnsch <- d
			}
		}
		lookupsMutex.RUnlock()
	}
}

func sender(ch chan string, c *net.UDPConn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer c.Close()
	for d := range ch {
		j, ok := getLookup(d)
		if !ok {
			debugLog("No lookup for domain:", d)
			continue
		}

		logErr(sendDns(d, j, c))
	}
	debugLog("Dns channel is closed")
}

func sendDns(d string, j *DnsJob, c *net.UDPConn) error {
	debugLog("Sending dns:", d)
	resolver := resolvers[rand.Intn(len(resolvers))]
	addr := &net.UDPAddr{IP: resolver, Port: 53}

	m := new(dns.Msg)
	m.SetQuestion(d, dns.TypeA)
	m.RecursionDesired = true

	msg, err2 := m.Pack()
	logErr(err2)
	_, err3 := c.WriteTo(msg, addr)
	logErr(err3)
	j.Lock()
	j.RequestTime = time.Now()
	j.Unlock()
	return err3
}

func reciever(c *net.UDPConn, wg *sync.WaitGroup) {
	defer wg.Done()

	for hasWork() {
		buff := make([]byte, 4096)
		c.SetReadDeadline(time.Now().Add(dnsTimeout))
		_, addr, err := c.ReadFrom(buff)

		logErr(err)
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			debugLog("Timeout reached. Number of jobs:", len(jobs))
			continue
		} else if ok {
			return
		}

		m := new(dns.Msg)
		m.Unpack(buff)

		if len(m.Question) != 1 {
			continue
		}

		name := m.Question[0].Name
		j, ok := getLookup(name)
		if !ok {
			debugLog("Recieved response with unwanted question:", name)
			continue
		}
		debugLog("Recieved response for:", name)
		j.Lock()
		j.Lookups[addr.String()] = m
		j.Unlock()
	}
}

func logErr(err error) bool {
	if err != nil {
		debugLog(err)
		return true
	}
	return false
}

func debugLog(v ...interface{}) {
	if debug {
		log.Println(v...)
	}
}

func worker(jobs *map[string]bool, wg *sync.WaitGroup) {
	defer wg.Done()
	for hasWork() {
		debugLog("Worker loop")
		jobsMutex.RLock()
		for d, _ := range *jobs {
			debugLog("Checking job status:", d)
			checkJobProgress(d, jobs, dnsch)
		}
		jobsMutex.RUnlock()
		shortSleep()
	}
	debugLog("No jobs left")
	close(dnsch)
}

func checkJobProgress(d string, jobs *map[string]bool, dnsch chan string) {
	fullDomain := dns.Fqdn(d)
	dnsJob, ok := getLookup(fullDomain)
	if !ok {
		createLookup(fullDomain)
		return
	}

	if len(dnsJob.Lookups) == 0 {
		return
	}

	msg := dnsJob.getAMsg()

	switch msg.MsgHdr.Rcode {
	case dns.RcodeSuccess:
		if dnsJob.NLookups < minVerifications {
			dnsJob.setNLookups(minVerifications)
			debugLog("Need more results for verification", len(dnsJob.Lookups))
		} else if verify(dnsJob) {
			if isCachedWildcard(msg, &wildcards) {
				debugLog("Cache hit for wildcard domain")
			} else {
				//wildcard check for domain d
				wd := BuildWildcardCheckDomain(fullDomain)
				wildcardDnsJob, ok := getLookup(wd)
				if !ok {
					debugLog("No wildcard check domain found, sending out dns for:", wd)
					createLookup(wd)
					return
				} else if len(wildcardDnsJob.Lookups) == 0 {
					return
				} else if isWildcard(dnsJob, wildcardDnsJob) {
					debugLog("Domain is a wildcard:", d)
					//TODO add to wildcard cache
					//TODO remove wd from lookups
					removeJob(d, jobs, "wildcard")
				} else {
					//Not a wildcard, lets print
					out(d, msg)
					removeJob(d, jobs, "success")
				}
			}
		} else {
			removeJob(d, jobs, "verfication_failed")
		}
		return
	case dns.RcodeNameError:
		removeJob(d, jobs, "NXDOMAIN")
	default:
		//TODO check if we want to abort all other Rcodes
		//There should be a retry mechanism
		removeJob(d, jobs, "unknown_Rcode")
		debugLog("Unhandled Rcode", msg.MsgHdr.Rcode, d, len(*jobs))
	}
}

func getLookup(d string) (*DnsJob, bool) {
	lookupsMutex.RLock()
	dnsJob, ok := lookups[d]
	lookupsMutex.RUnlock()
	return dnsJob, ok
}

func createLookup(d string) {
	debugLog("Creating new dns job:", d)
	lookupsMutex.Lock()
	lookups[d] = &DnsJob{Name: d, Lookups: map[string]*dns.Msg{}, NLookups: 1}
	lookupsMutex.Unlock()
}

func hasWork() bool {
	return !inputDone || len(jobs) > 0
}

func removeJob(d string, jobs *map[string]bool, reason string) {
	debugLog("Job done:", d, reason)
	delete(*jobs, d)
	clearLookups(dns.Fqdn(d))
}

func clearLookups(d string) {
	lookupsMutex.Lock()
	delete(lookups, d)
	lookupsMutex.Unlock()
}

func verify(j *DnsJob) bool {
	//TODO improve verification algorithm
	//TODO penalize bad resolvers
	msgs := j.Lookups
	j.Lock()
	defer j.Unlock()
	votes := 0
	var m *dns.Msg
	for _, msg := range msgs {
		m = msg
		if len(msg.Answer) > 0 {
			votes++
		} else {
			votes--
		}
	}
	d := m.Question[0].Name
	if votes < 1 {
		debugLog("Verification failed for domain:", d)
		return false
	}
	debugLog("Verification succeded for domain:", d)

	return true
}

func (dnsJob *DnsJob) setNLookups(n int) {
	dnsJob.Lock()
	dnsJob.RequestTime = time.Time{}
	dnsJob.NLookups = n
	dnsJob.Unlock()
}

func (dnsJob *DnsJob) getAMsg() *dns.Msg {
	dnsJob.Lock()
	defer dnsJob.Unlock()
	for _, msg := range dnsJob.Lookups {
		return msg
	}
	return nil
}

func isCachedWildcard(msg *dns.Msg, cache *map[string]map[string]bool) bool {
	levels := GenLevels(msg.Question[0].Name)
	msg_addrs := GetIpv4Addrs(*msg)

	for i := 0; i < len(levels)-1; i++ {
		if val, ok := (*cache)[levels[i]]; ok {
			if KeyIntersect(msg_addrs, val) {
				debugLog(msg_addrs, val)
				return true
			}
		}
	}
	return false
}

func isWildcard(j, wj *DnsJob) bool {
	if len(wj.Lookups) == 0 {
		return false
	}

	msg := j.getAMsg()
	wmsg := wj.getAMsg()

	if len((*wmsg).Answer) == 0 {
		return false
	}

	maddr := GetIpv4Addrs(*msg)
	waddr := GetIpv4Addrs(*wmsg)

	return KeyIntersect(maddr, waddr)
}

func KeyIntersect(a map[string]bool, b map[string]bool) bool {
	for k, _ := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

func GenLevels(d string) []string {
	split := strings.Split(strings.Trim(d, " ."), ".")
	var levels []string

	for i := 0; i < len(split); i++ {
		levels = append(levels, strings.Join(split[i:], "."))
	}
	return levels
}

func GetIpv4Addrs(msg dns.Msg) map[string]bool {
	addrs := map[string]bool{}
	for _, answer := range msg.Answer {
		if a, ok := answer.(*dns.A); ok {
			addrs[a.A.String()] = true
		}
	}
	return addrs
}

func BuildWildcardCheckDomain(d string) string {
	base := strings.SplitN(d, ".", 2)[1]
	return strings.ToLower(GetMD5Hash(base+"Salt: 42")) + "." + base
}

func printWildcards() {
	for wildcard, ips := range wildcards {
		s := "*." + wildcard
		if verbose {
			for ip, _ := range ips {
				s += " " + ip
			}
		}
		fmt.Println(s)
	}
}

func out(d string, msg *dns.Msg) {
	s := d
	if verbose {
		for ip, _ := range GetIpv4Addrs(*msg) {
			s += " " + ip
		}
	}
	fmt.Println(s)
}

func parseFlags() {
	flag.StringVar(&resolverFile, "r", "", "Optional but recommended resolvers file, newline separated resolver ips")
	flag.IntVar(&nGoroutines, "c", 2, "Number of \"threads\" working, tune this for optimum performance.")
	flag.BoolVar(&verbose, "v", false, "Enables ip numbers printing to output")
	flag.BoolVar(&debug, "debug", false, "Outputs debug information")
	flag.DurationVar(&dnsTimeout, "dt", 1000*time.Millisecond, "DNS Timeout in millisecods")
	flag.IntVar(&nConcurrentJobs, "cj", 1000, "Number of concurrent jobs")
	flag.IntVar(&minVerifications, "mv", 3, "Number of required verification dns requests")

	help := flag.Bool("-help", false, "Prints help text")
	flag.BoolVar(help, "h", *help, "alias for --help")
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

}

func getResolvers() []net.IP {
	ips := famousResolvers

	if resolverFile != "" {
		ips = FileToSlice(resolverFile)
	}

	local_resolvers := []net.IP{}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil {
			local_resolvers = append(local_resolvers, parsed)
		}
	}

	return local_resolvers
}

func FileToSlice(f string) []string {
	file, err := os.Open(f)

	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return lines
}

func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func shortSleep() {
	time.Sleep(50 * time.Millisecond)
}
