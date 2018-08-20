package tcp

import (
	"fmt"
	//"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/outputs"

	"github.com/elastic/beats/heartbeat/monitors"
)

func init() {
	monitors.RegisterActive("tcp", create)
}

var debugf = logp.MakeDebug("tcp")

type connURL struct {
	Scheme string
	Host   string
	Ports  []uint16
}

func create(
	info monitors.Info,
	cfg *common.Config,
) ([]monitors.Job, error) {
	config := DefaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return nil, err
	}

	tls, err := outputs.LoadTLSConfig(config.TLS)
	if err != nil {
		return nil, err
	}

	defaultScheme := "tcp"
	if tls != nil {
		defaultScheme = "ssl"
	}

	localAddrs, count, err := monitors.CollectLocalAddr(config.Interface, defaultScheme)
	if err != nil {
		return nil, err
	} else {
		if count != 0 {
			debugf("http bind interface parse: {")
			for _, localAddr := range localAddrs {
				for _, localIP := range localAddr.IPs {
					debugf("IP: %s, port: %d", localIP.IP.String(), localIP.Port)
				}
			}
			debugf("Number of destination addresses: %d", count)
			debugf("}")
		}
	}

	if config.Socks5.URL != "" && !config.Socks5.LocalResolve {
		var jobs []monitors.Job
		for _, localAddr := range localAddrs {
			addrs, err := collectHosts(&config, defaultScheme, localAddr.Key)
			if err != nil {
				return nil, err
			}
			for _, addr := range addrs {
				scheme, host := addr.Scheme, addr.Host
				for _, port := range addr.Ports {
					job, err := newTCPMonitorHostJob(scheme, host, port,
						localAddr, tls, &config)
					if err != nil {
						return nil, err
					}
					jobs = append(jobs, job)
				}
			}
		}
		return jobs, nil
	}

	jobs := make([]monitors.Job, count)
	i := 0
	for _, localAddr := range localAddrs {
		addrs, err := collectHosts(&config, defaultScheme, localAddr.Key)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			jobs[i], err = newTCPMonitorIPsJob(addr, localAddr, tls, &config)
			if err != nil {
				return nil, err
			}
			i++
		}
	}

	return jobs, nil
}

func collectHosts(config *Config, defaultScheme string, key string) ([]connURL, error) {
	var addrs []connURL
	var hosts []string

	hosts = config.Interface[key]
	for _, h := range hosts {
		scheme := defaultScheme
		host := ""
		u, err := url.Parse(h)

		if err != nil || u.Host == "" {
			host = h
		} else {
			scheme = u.Scheme
			host = u.Host
		}
		debugf("Add tcp endpoint '%v://%v'.", scheme, host)

		switch scheme {
		case "tcp", "plain", "tls", "ssl":
		default:
			err := fmt.Errorf("'%v' is no supported connection scheme in '%v'", scheme, h)
			return nil, err
		}

		pair := strings.SplitN(host, ":", 2)
		ports := config.Ports
		if len(pair) == 2 {
			port, err := strconv.ParseUint(pair[1], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("'%v' is no valid port number in '%v'", pair[1], h)
			}

			ports = []uint16{uint16(port)}
			host = pair[0]
		} else if len(config.Ports) == 0 {
			return nil, fmt.Errorf("host '%v' missing port number", h)
		}

		addrs = append(addrs, connURL{
			Scheme: scheme,
			Host:   host,
			Ports:  ports,
		})
	}
	return addrs, nil
}
