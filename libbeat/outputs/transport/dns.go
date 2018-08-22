package transport

import (
	"errors"
	//"fmt"
	"math/rand"
	"net"
	//"os"
	"strings"
	"sync"
	"time"

	mkdns "github.com/miekg/dns"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

const (
	DnsModeIPV4 = "ipv4"
	DnsModeIPV6 = "ipv6"
	DnsModeAll  = "all"
)

type Dns struct {
	Addrs   []string `config:"addrs"`
	Timeout int      `config:"timeout"`
	Mode    string   `config:"mode"`
}

const (
	defaultPort string = "53"

	defaultTimeout int = 3

	TypeA    = mkdns.TypeA
	TypeAAAA = mkdns.TypeAAAA
)

var DefaultDnsSet = Dns{
	Timeout: -1,
	Mode:    DnsModeIPV4,
}

func ParseDns(domain string, dns Dns, dnsType uint16) ([]net.IP, error) {

	if domain == "" || len(dns.Addrs) <= 0 || (dnsType != TypeA && dnsType != TypeAAAA) {
		return nil, errors.New("")
	}

	if dns.Timeout < 0 {
		dns.Timeout = defaultTimeout
	}

	var dnsResult []net.IP
	var err error

	for _, addr := range dns.Addrs {
		//go func() {
		if strings.Contains(addr, ":") != true {
			addr = net.JoinHostPort(addr, defaultPort)
		}
		m1 := new(mkdns.Msg)
		m1.Id = mkdns.Id()
		m1.RecursionDesired = true
		if dnsType == TypeA {
			m1.SetQuestion(mkdns.Fqdn(domain), mkdns.TypeA)
		} else if dnsType == TypeAAAA {
			m1.SetQuestion(mkdns.Fqdn(domain), mkdns.TypeAAAA)
		}

		c := new(mkdns.Client)
		c.Timeout = time.Duration(dns.Timeout) * time.Second
		in, _, parseErr := c.Exchange(m1, addr)

		if parseErr == nil {
			if in.Rcode != mkdns.RcodeSuccess {
				err = errors.New("dns recode faild.")
				continue
			}

			for _, answer := range in.Answer {
				if dnsType == TypeA {
					if result, ok := answer.(*mkdns.A); ok {
						dnsResult = append(dnsResult, result.A)
					}
				} else if dnsType == TypeAAAA {
					if result, ok := answer.(*mkdns.AAAA); ok {
						dnsResult = append(dnsResult, result.AAAA)
					}
				}
			}

			if len(dnsResult) <= 0 {
				err = errors.New("No parse result.")
				continue
			} else {
				return dnsResult, nil
			}
		}
		err = parseErr
		//		}()
	}
	return nil, err
}

func DnsLookup(domain string, dns Dns) ([]net.IP, error) {

	var dnsResult []net.IP
	var dnsIPV4 []net.IP
	var dnsIPV6 []net.IP
	var IPV4Err error
	var IPV6Err error
	var wg sync.WaitGroup

	if dns.Mode != DnsModeIPV4 && dns.Mode != DnsModeIPV6 && dns.Mode != DnsModeAll {
		dns.Mode = DnsModeIPV4
	}

	if dns.Mode == DnsModeIPV4 || dns.Mode == DnsModeAll {
		wg.Add(1)
		go func() {
			dnsIPV4, IPV4Err = ParseDns(domain, dns, TypeA)
			wg.Done()
		}()
	}

	if dns.Mode == DnsModeIPV6 || dns.Mode == DnsModeAll {
		wg.Add(1)
		go func() {
			dnsIPV6, IPV6Err = ParseDns(domain, dns, TypeAAAA)
			wg.Done()
		}()
	}

	wg.Wait()

	if IPV4Err != nil && IPV6Err != nil {
		if dns.Mode == DnsModeAll {
			return nil, IPV4Err
		} else if dns.Mode == DnsModeIPV4 {
			return nil, IPV4Err
		} else {
			return nil, IPV6Err
		}
	}

	if IPV4Err == nil {
		dnsResult = append(dnsResult, dnsIPV4...)
	}
	if IPV6Err == nil {
		dnsResult = append(dnsResult, dnsIPV6...)
	}

	return dnsResult, nil
}

func dnsIPtoString(domain string, dns Dns) ([]string, error) {
	var results []string

	dnsResults, err := DnsLookup(domain, dns)
	if err != nil {
		return nil, err
	}

	for _, dnsResult := range dnsResults {
		results = append(results, dnsResult.String())
	}

	return results, nil
}

func DnsLookupAny(domain string, dns Dns) (*net.IPAddr, error) {

	dnsResults, err := DnsLookup(domain, dns)
	if err != nil {
		return nil, err
	}

	if len(dnsResults) > 1 {
		i := rand.Intn(len(dnsResults))
		return &net.IPAddr{IP: dnsResults[i]}, nil
	}

	return &net.IPAddr{IP: dnsResults[0]}, nil
}

/*
func main() {
	addrs := []string{"114.114.114.114", "8.8.8.8:53"}
	dns := Dns{
		Addrs:   addrs,
		Timeout: 3,
	}
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s [any|all]\n", os.Args[0])
		return
	}
	if os.Args[1] == "any" {
		fmt.Println("any")
		result, err := DnsLookupAny("www.google.cn", dns)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(result.IP.String())
	} else if os.Args[1] == "all" {
		fmt.Println("all")
		result, err := DnsLookup("www.google.cn", dns)
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, ip := range result {
			fmt.Println(ip.String())
		}
	}
}*/
