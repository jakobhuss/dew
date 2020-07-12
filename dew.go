package main

import "fmt"
import "flag"
import "bufio"
import "os"
import "log"
import "net"
import "sync"
import "strings"
import "math/rand"
import "github.com/miekg/dns"

//flags
var resolver_file string
var num_goroutines int
var verbose bool
var pw bool

//constants
var famousResolvers = []string{"1.0.0.1", "1.1.1.1", "149.112.112.112", "176.103.130.130", "176.103.130.131", "185.228.168.9", "185.228.169.9", "198.101.242.72", "207.67.222.222", "208.67.220.220", "208.67.222.222", "23.253.163.53", "64.6.64.6", "64.6.65.6", "8.8.4.4", "8.8.8.8", "9.9.9.9"}

var mutex = &sync.Mutex{}
var wildcards = map[string]map[string]bool{}
var resolvers []net.IP

func main() {
	parseFlags()

	var wg sync.WaitGroup
	ch := make(chan string)

	for i := 0; i < num_goroutines; i++ {
		wg.Add(1)
		go worker(resolvers, ch, &wg)
	}

	count := 0
	for scanner := bufio.NewScanner(os.Stdin); scanner.Scan(); count++ {
		ch <- scanner.Text()
	}

	close(ch)

	wg.Wait()
	log.Println("Number of input domains:", count)

	printWildcards()
}

func worker(resolvers []net.IP, ch chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	i := 0
	for d := range ch {
		var msg *dns.Msg
		for j := 0; j < 5; j++ {
			var err error
			msg, err = query_resolver(d, resolvers[i%len(resolvers)])
			i++
			if err != nil {
				// TODO error handling
				log.Println(err)
				continue
			}
			break
		}

		if msg == nil {
			continue
		}

		if msg.MsgHdr.Rcode > 0 {
			log.Println("Rcode for msg:", msg.MsgHdr.Rcode, dns.RcodeToString[msg.MsgHdr.Rcode])
			continue
		}

		if len(msg.Answer) == 0 {
			continue
		}

		if is_wildcard(d, msg) {
			continue
		}

		out(d, msg)
	}
}

func query_resolver(q string, resolver net.IP) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(q), dns.TypeA)
	return dns.Exchange(m, resolver.String()+":53")
}

func is_wildcard(d string, msg *dns.Msg) bool {
	levels := GenLevels(d)
	msg_addrs := GetIpv4Addrs(*msg)

	for i := 1; i < len(levels)-1; i++ {
		if val, ok := wildcards[levels[i]]; ok {
			if KeyIntersect(msg_addrs, val) {
				log.Println(msg_addrs, val)
				return true
			}
			return true
		}
	}

	// no cached entry found
	// do wildcard lookup

	var wildcard string
	var addrs map[string]bool
	for i := 1; i < len(levels)-1; i++ {
		resolver := resolvers[rand.Intn(len(resolvers))]
		check_msg, err := query_resolver(RandString(20)+"."+levels[i], resolver)
		if err != nil {
			//TODO this error should be handled better
			//returning true here is wrong
			log.Println(err)
			return true
		}

		if len(check_msg.Answer) == 0 {
			//this lvl is not a wildcard
			break
		}

		wildcard = levels[i]
		addrs = GetIpv4Addrs(*check_msg)
	}

	if wildcard != "" {
		log.Println("Wildcard found *." + wildcard)
		if val, ok := wildcards[wildcard]; ok {
			for ip, _ := range addrs {
				if _, ok := val[ip]; !ok {
					val[ip] = true
					log.Println("Appending new wildcard ip:", ip)
				}
			}
		} else {
		  mutex.Lock()
			wildcards[wildcard] = addrs
		  mutex.Unlock()
			log.Println("*."+wildcard, addrs)
		}
	}

	if KeyIntersect(addrs, msg_addrs) {
		log.Println("This is wildcard with addrs:", addrs)
		return true
	}

	log.Println("Found unique ips:", msg_addrs, addrs)
	return false
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

func RandString(n int) string {
	const lower = "abcdefghijklmnopqrstuvwxyz"
	bytes := make([]byte, n)
	for i := range bytes {
		bytes[i] = lower[rand.Intn(len(lower))]
	}

	return string(bytes)
}

func printWildcards() {
	for k, _ := range wildcards {
		fmt.Println("*." + k)
	}
}

func out(d string, msg *dns.Msg) {
	if pw {
		return
	}

	fmt.Print(d)
	if verbose {
		for k, _ := range GetIpv4Addrs(*msg) {
			fmt.Print(" ", k)
		}
	}
	fmt.Println()
}

func parseFlags() {
	flag.StringVar(&resolver_file, "r", "", "Optional but recommended resolvers file, newline separated resolver ips")
	flag.IntVar(&num_goroutines, "c", 20, "Number of \"threads\" working, tune this for optimum performance.")
	flag.BoolVar(&verbose, "v", false, "Enables ip numbers printing to output")
	flag.BoolVar(&pw, "pw", false, "Prints all found wildcard domains")

  help := flag.Bool("help", false, "Prints help text")
  flag.BoolVar(help, "h", *help, "alias for -help")
	flag.Parse()

  if *help {
    flag.Usage()
    os.Exit(0)
  }

	resolvers = get_resolvers()
}

func get_resolvers() []net.IP {
	ips := famousResolvers

	if resolver_file != "" {
		ips = FileToSlice(resolver_file)
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
