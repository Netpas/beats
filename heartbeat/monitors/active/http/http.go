package http

import (
	"bytes"
	"net"
	"net/http"
	"net/url"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/outputs"
	"github.com/elastic/beats/libbeat/outputs/transport"

	"github.com/elastic/beats/heartbeat/monitors"
)

func init() {
	monitors.RegisterActive("http", create)
}

var debugf = logp.MakeDebug("http")

func create(
	info monitors.Info,
	cfg *common.Config,
) ([]monitors.Job, error) {
	config := defaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return nil, err
	}

	tls, err := outputs.LoadTLSConfig(config.TLS)
	if err != nil {
		return nil, err
	}

	var body []byte
	var enc contentEncoder
	if config.Check.Request.SendBody != "" {
		var err error
		compression := config.Check.Request.Compression
		enc, err = getContentEncoder(compression.Type, compression.Level)
		if err != nil {
			return nil, err
		}

		buf := bytes.NewBuffer(nil)
		err = enc.Encode(buf, bytes.NewBufferString(config.Check.Request.SendBody))
		if err != nil {
			return nil, err
		}

		body = buf.Bytes()
	}

	localAddrs, count, err := monitors.CollectLocalAddr(config.Interface, "http")
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

	validator := makeValidateResponse(&config.Check.Response)

	jobs := make([]monitors.Job, count)
	i := 0

	if config.ProxyURL != "" {
		for _, localAddr := range localAddrs {
			transport, err := newRoundTripper(&config, tls, localAddr)
			if err != nil {
				return nil, err
			}
			urls := config.Interface[localAddr.Key]
			for _, url := range urls {
				jobs[i], err = newHTTPMonitorHostJob(url, &config, transport, enc, body, validator, localAddr.Host)
				if err != nil {
					return nil, err
				}
				i++
			}
		}
	} else {
		for _, localAddr := range localAddrs {
			urls := config.Interface[localAddr.Key]
			for _, url := range urls {
				jobs[i], err = newHTTPMonitorIPsJob(&config, url, tls, enc, body, validator, localAddr)
				if err != nil {
					return nil, err
				}
				i++
			}
		}
	}

	return jobs, nil
}

func newRoundTripper(config *Config,
	tls *transport.TLSConfig,
	localAddr monitors.BindLocalAddr,
) (*http.Transport, error) {
	var proxy func(*http.Request) (*url.URL, error)
	if config.ProxyURL != "" {
		url, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, err
		}
		proxy = http.ProxyURL(url)
	}
	var dialer transport.Dialer
	var localIPs []net.TCPAddr

	for _, localIP := range localAddr.IPs {
		localIPs = append(localIPs, net.TCPAddr{
			IP:   localIP.IP,
			Port: localIP.Port,
			Zone: localIP.Zone,
		})
	}

	if len(localAddr.IPs) <= 0 {
		dialer = transport.NetDialer(config.Timeout)
	} else {
		dialer = transport.NetBindDialer(config.Timeout, localIPs, config.Dns)
	}
	tlsDialer, err := transport.TLSDialer(dialer, tls, config.Timeout)
	if err != nil {
		return nil, err
	}

	return &http.Transport{
		Proxy:             proxy,
		Dial:              dialer.Dial,
		DialTLS:           tlsDialer.Dial,
		DisableKeepAlives: true,
	}, nil
}
