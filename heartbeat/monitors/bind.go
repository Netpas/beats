package monitors

import (
	//"fmt"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

var (
	ipFormatErr  = errors.New("interface: The format of the bind address is error.")
	interfaceErr = errors.New("interface: Parameter error.")
)

const (
	IPV4 = iota + 1
	IPV6
)

const (
	DefaultInterfaceMode = "default"
)

type IPAddr struct {
	IP     net.IP
	Port   int
	IPtype int
	Zone   string
}

type BindLocalAddr struct {
	IPs  []IPAddr
	Host string
	Key  string
}

func parseNetworkCard(eth string) ([]IPAddr, error) {
	var addr []IPAddr

	ief, err := net.InterfaceByName(eth)
	if err != nil {
		return nil, err
	}
	ethAddrs, err := ief.Addrs()
	if err != nil {
		return nil, err
	}

	for _, ethAddr := range ethAddrs {
		ip := ethAddr.(*net.IPNet).IP
		if ip.To4() != nil {
			addr = append(addr, IPAddr{
				IP:     ip,
				IPtype: IPV4,
			})
		} else {
			addr = append(addr, IPAddr{
				IP:     ip,
				IPtype: IPV6,
				Zone:   eth,
			})
		}
	}

	return addr, nil
}

func getIPV6InterfaceName(addr string) (string, error) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, netInterface := range netInterfaces {
		ief, err := net.InterfaceByName(netInterface.Name)
		if err != nil {
			return "", err
		}

		ethAddrs, err := ief.Addrs()
		if err != nil {
			return "", err
		}
		for _, ethAddr := range ethAddrs {
			// fmt.Println(ethAddr.(*net.IPNet).IP.String())
			if ethAddr.(*net.IPNet).IP.String() == addr {
				return netInterface.Name, nil
			}
		}

	}
	return "", errors.New("No matching network card name found")
}

func parseIPAddrs(ip string) ([]IPAddr, error) {

	var addr []IPAddr

	ip = strings.Trim(ip, " ")

	flag := strings.HasPrefix(ip, "[")

	if (flag && strings.Contains(ip, "]:")) ||
		((flag == false) && strings.Contains(ip, ":")) {
		host, tmpPort, err := net.SplitHostPort(ip)
		if err != nil {
			return nil, err
		}

		port, err := strconv.Atoi(tmpPort)
		if err != nil {
			return nil, err
		}
		localIP := net.ParseIP(host)
		if localIP == nil {
			return nil, ipFormatErr
		}
		if localIP.To4() != nil {
			addr = append(addr, IPAddr{
				IP:     localIP,
				Port:   port,
				IPtype: IPV4,
			})
		} else {
			zone, err := getIPV6InterfaceName(host)
			if err != nil {
				return nil, err
			}
			addr = append(addr, IPAddr{
				IP:     localIP,
				Port:   port,
				IPtype: IPV6,
				Zone:   zone,
			})
		}

	} else {
		if flag {
			ip = strings.Trim(ip, "[]")
		}
		localIP := net.ParseIP(ip)
		if localIP == nil {
			return nil, ipFormatErr
		}
		if localIP.To4() != nil {
			addr = append(addr, IPAddr{
				IP:     localIP,
				IPtype: IPV4,
			})
		} else {
			zone, err := getIPV6InterfaceName(ip)
			if err != nil {
				return nil, err
			}
			addr = append(addr, IPAddr{
				IP:     localIP,
				IPtype: IPV6,
				Zone:   zone,
			})
		}
	}

	return addr, nil
}

func convertIP(ip string) (string, error) {
	ss := strings.SplitN(ip, "-", -1)
	ipAddr := strings.Join(ss, ".")
	return ipAddr, nil
}

func CollectLocalAddr(localInterfaces map[string][]string,
	sechmem string) ([]BindLocalAddr, int, error) {

	var localAddrs []BindLocalAddr
	var count int = 0
	var valueLen int = 0

	for key, value := range localInterfaces {
		if sechmem == "icmp" {
			if strings.Contains(key, "]:") ||
				(strings.Contains(key, ":") && strings.Contains(key, "-")) {
				var icmpBindErr string
				fmt.Sprintf(icmpBindErr,
					"icmp.interface: %s - The format of the bind address is error.",
					key)
				return nil, 0, errors.New(icmpBindErr)
			}
		}

		if len(value) <= 0 {
			var hostErr string
			fmt.Sprintf(hostErr, "interface: %s : Hosts does not exist.", key)
			return nil, 0, errors.New(hostErr)
		}
		valueLen += len(value)
		if key == DefaultInterfaceMode {
			// default
			localAddrs = append([]BindLocalAddr{}, BindLocalAddr{
				Key:  key,
				Host: key,
			})
			count = 1
			valueLen = len(value)
			break
		} else if strings.HasPrefix(key, "*") {
			ipAddr, err := parseNetworkCard(strings.TrimPrefix(key, "*"))
			if err != nil {
				return nil, 0, err
			}
			localAddrs = append(localAddrs, BindLocalAddr{
				IPs:  ipAddr,
				Host: strings.TrimPrefix(key, "*"),
				Key:  key,
			})
		} else if strings.Contains(key, "-") {
			newIPAddr, err := convertIP(key)
			if err != nil {
				return nil, 0, err
			}
			ipAddr, err := parseIPAddrs(newIPAddr)
			if err != nil {
				return nil, 0, err
			}
			localAddrs = append(localAddrs, BindLocalAddr{
				IPs:  ipAddr,
				Host: newIPAddr,
				Key:  key,
			})
		} else {
			ipAddr, err := parseIPAddrs(key)
			if err != nil {
				return nil, 0, err
			}
			localAddrs = append(localAddrs, BindLocalAddr{
				IPs:  ipAddr,
				Host: key,
				Key:  key,
			})
		}
		count++
	}

	if count <= 0 {
		return nil, 0, interfaceErr
	}

	count = valueLen
	return localAddrs, count, nil
}

/*
func main() {
	list := make(map[string][]string, 7)
	list["*ens33"] = []string{"123.34.56.78", "23.4.4.4"}
	list["172-34-45-35"] = []string{"123.34.56.78", "23.4.4.5"}
	list["172-34-45-45:8000"] = []string{"123.34.56.78", "23.4.4.6"}
	list["[2000::1:2345:6789:abcd]"] = []string{"123.34.56.78", "23.4.4.7"}
	list["[2000::1:2345:6789:abcd]:844"] = []string{"123.34.56.78", "23.4.4.7"}

	bindLocalAddr, count, err := CollectLocalAddr(list, "http")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("count: %d\n", count)

	for _, localAddrs := range bindLocalAddr {
		fmt.Printf("map[%s] --- > : \n", localAddrs.Key)
		for _, ip := range localAddrs.IPs {
			fmt.Printf("IP: %s, prot: %d, IPtype: %d\n", ip.IP.String(), ip.Port, ip.IPtype)
		}
		fmt.Printf("\n")
	}

}*/
