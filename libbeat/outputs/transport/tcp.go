package transport

import (
	"fmt"
	"net"
	"time"

	"github.com/elastic/beats/libbeat/logp"
)

func NetDialer(timeout time.Duration) Dialer {
	return DialerFunc(func(network, address string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		default:
			return nil, fmt.Errorf("unsupported network type %v", network)
		}

		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		addresses, err := net.LookupHost(host)
		if err != nil {
			logp.Warn(`DNS lookup failure "%s": %v`, host, err)
			return nil, err
		}

		// dial via host IP by randomized iteration of known IPs
		dialer := &net.Dialer{Timeout: timeout}
		return dialWith(dialer, network, host, addresses, port)
	})
}

func NetBindDialer(timeout time.Duration,
	locals []net.TCPAddr,
	dnsParse Dns) Dialer {
	return DialerFunc(func(network, address string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		default:
			return nil, fmt.Errorf("unsupported network type %v", network)
		}

		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		var addresses []string
		var errDns error

		if dnsParse.Addrs == nil {
			addresses, errDns = net.LookupHost(host)
		} else {
			addresses, errDns = dnsIPtoString(host, dnsParse)
		}
		if errDns != nil {
			logp.Warn(`DNS lookup failure "%s": %v`, host, err)
			return nil, errDns
		}
		var addrV4, addrV6 []string
		for _, address := range addresses {
			if (net.ParseIP(address)).To4() != nil {
				addrV4 = append(addrV4, address)
			} else {
				addrV6 = append(addrV4, address)
			}
		}

		// dial via host IP by randomized iteration of known IPs
		var dialer *net.Dialer
		var conn net.Conn
		var connErr error
		for _, local := range locals {
			conn = nil
			connErr = nil
			if local.IP.To4() != nil {
				if len(addrV4) <= 0 {
					continue
				}
				dialer = &net.Dialer{Timeout: timeout, LocalAddr: &local}
				conn, connErr = dialWith(dialer, network, host, addrV4, port)
			} else {
				if len(addrV6) <= 0 {
					continue
				}
				dialer = &net.Dialer{Timeout: timeout, LocalAddr: &local}
				conn, connErr = dialWith(dialer, network, host, addrV6, port)
			}
			if connErr == nil {
				break
			}
		}
		if connErr == nil && conn == nil {
			return nil, fmt.Errorf("The binding address and the remote address do not match.")
		}
		return conn, connErr
	})
}
