package tcp

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/outputs/transport"

	"github.com/elastic/beats/heartbeat/look"
	"github.com/elastic/beats/heartbeat/monitors"
	"github.com/elastic/beats/heartbeat/monitors/active/dialchain"
	"github.com/elastic/beats/heartbeat/reason"
)

func newTCPMonitorHostJob(
	scheme, host string, port uint16,
	localAddr monitors.BindLocalAddr,
	tls *transport.TLSConfig,
	config *Config,
) (monitors.Job, error) {
	typ := config.Name
	timeout := config.Timeout
	jobName := jobName(typ, jobType(scheme), host, []uint16{port})
	validator := makeValidateConn(config)
	pingAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	var localIPs []net.TCPAddr

	for _, localIP := range localAddr.IPs {
		localIPs = append(localIPs, net.TCPAddr{
			IP:   localIP.IP,
			Port: localIP.Port,
			Zone: localIP.Zone,
		})
	}
	taskDialer, err := buildDialerChain(scheme, tls, config, localIPs)
	if err != nil {
		return nil, err
	}

	return monitors.MakeSimpleJob(jobName, typ, func() (common.MapStr, error) {
		event := common.MapStr{
			"scheme":    scheme,
			"port":      port,
			"host":      host,
			"interface": localAddr.Host,
		}
		dialer, err := taskDialer.BuildWithMeasures(event)
		if err != nil {
			return event, err
		}

		results, err := pingHost(dialer, pingAddr, timeout, validator)
		event.Update(results)
		return event, err
	}), nil
}

func newTCPMonitorIPsJob(
	addr connURL,
	localAddr monitors.BindLocalAddr,
	tls *transport.TLSConfig,
	config *Config,
) (monitors.Job, error) {
	typ := config.Name
	timeout := config.Timeout
	jobType := jobType(addr.Scheme)
	jobName := jobName(typ, jobType, addr.Host, addr.Ports)
	validator := makeValidateConn(config)
	var localIPs []net.TCPAddr

	for _, localIP := range localAddr.IPs {
		localIPs = append(localIPs, net.TCPAddr{
			IP:   localIP.IP,
			Port: localIP.Port,
			Zone: localIP.Zone,
		})
	}

	dialerFactory, err := buildHostDialerChainFactory(addr.Scheme, tls, config, localIPs)
	if err != nil {
		return nil, err
	}

	pingFactory := createPingFactory(dialerFactory, addr, timeout, validator)
	if ip := net.ParseIP(addr.Host); ip != nil {
		debugf("Make TCP by IP job: %v:%v", ip, addr.Ports)
		return monitors.MakeByIPJob(localAddr.Host, jobName, typ, ip, pingFactory)
	}

	debugf("Make TCP by Host job: %v:%v (mode=%#v)", addr.Host, addr.Ports, config.Mode)
	return monitors.MakeByHostJob(localAddr.Host, jobName, typ, addr.Host, config.Mode, pingFactory, config.Dns)
}

func createPingFactory(
	makeDialerChain func(string) *dialchain.DialerChain,
	addr connURL,
	timeout time.Duration,
	validator ConnCheck,
) func(*net.IPAddr) monitors.TaskRunner {
	fields := common.MapStr{"scheme": addr.Scheme}

	return monitors.MakePingAllIPPortFactory(fields, addr.Ports,
		func(ip *net.IPAddr, port uint16) (common.MapStr, error) {
			host := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
			pingAddr := net.JoinHostPort(addr.Host, strconv.Itoa(int(port)))

			event := common.MapStr{}
			dialer, err := makeDialerChain(host).BuildWithMeasures(event)
			if err != nil {
				return event, err
			}
			results, err := pingHost(dialer, pingAddr, timeout, validator)
			if err != nil {
				return event, err
			}
			event.Update(results)

			return event, err
		})
}

func pingHost(
	dialer transport.Dialer,
	host string,
	timeout time.Duration,
	validator ConnCheck,
) (common.MapStr, reason.Reason) {
	start := time.Now()
	deadline := start.Add(timeout)

	conn, err := dialer.Dial("tcp", host)
	if err != nil {
		debugf("dial failed with: %v", err)
		return nil, reason.IOFailed(err)
	}

	defer conn.Close()
	if validator == nil {
		// no additional validation step => ping success
		return common.MapStr{}, nil
	}

	if err := conn.SetDeadline(deadline); err != nil {
		debugf("setting connection deadline failed with: %v", err)
		return nil, reason.IOFailed(err)
	}

	validateStart := time.Now()
	err = validator.Validate(conn)
	if err != nil && err != errRecvMismatch {
		debugf("check failed with: %v", err)
		return nil, reason.IOFailed(err)
	}

	end := time.Now()
	event := common.MapStr{
		"validate_rtt": look.RTT(end.Sub(validateStart)),
	}
	if err != nil {
		event["error"] = reason.FailValidate(err)
	}
	return event, nil
}

func isTLSAddr(scheme string) bool {
	return scheme == "tls" || scheme == "ssl"
}

func jobType(scheme string) string {
	switch scheme {
	case "tls", "ssl":
		return scheme
	}
	return "plain"
}

func jobName(typ, jobType, host string, ports []uint16) string {
	var h string
	if len(ports) == 1 {
		h = fmt.Sprintf("%v:%v", host, ports[0])
	} else {
		h = fmt.Sprintf("%v:%v", host, ports)
	}
	return fmt.Sprintf("%v-%v@%v", typ, jobType, h)
}

func buildDialerChain(
	scheme string,
	tls *transport.TLSConfig,
	config *Config,
	localAddr []net.TCPAddr,
) (*dialchain.DialerChain, error) {
	var netDialer dialchain.NetDialer

	if len(localAddr) <= 0 {
		netDialer = dialchain.TCPDialer("tcp_connect_rtt", config.Timeout)
	} else {
		netDialer = dialchain.TCPBindDialer("tcp_connect_rtt", config.Timeout,
			localAddr, config.Dns)
	}

	d := &dialchain.DialerChain{
		Net: netDialer,
	}
	if config.Socks5.URL != "" {
		d.AddLayer(dialchain.SOCKS5Layer("socks5_connect_rtt", &config.Socks5))
	}
	if isTLSAddr(scheme) {
		d.AddLayer(dialchain.TLSLayer("tls_handshake_rtt", tls, config.Timeout))
	}

	if err := d.TestBuild(); err != nil {
		return nil, err
	}
	return d, nil
}

func buildHostDialerChainFactory(
	scheme string,
	tls *transport.TLSConfig,
	config *Config,
	localAddr []net.TCPAddr,
) (func(string) *dialchain.DialerChain, error) {
	template, err := buildDialerChain(scheme, tls, config, localAddr)
	if err != nil {
		return nil, err
	}

	withProxy := config.Socks5.URL != ""
	return func(addr string) *dialchain.DialerChain {
		if withProxy {
			d := template.Clone()
			d.Layers[0] = dialchain.ConstAddrLayer(addr, d.Layers[0])
			return d
		}

		if len(localAddr) <= 0 {
			return &dialchain.DialerChain{
				Net:    dialchain.ConstAddrDialer("tcp_connect_rtt", addr, config.Timeout),
				Layers: template.Layers,
			}
		} else {
			return &dialchain.DialerChain{
				Net:    dialchain.ConstAddrBindDialer("tcp_connect_rtt", addr, config.Timeout, localAddr),
				Layers: template.Layers,
			}
		}
	}, nil
}
