package tcp

import (
	"errors"
	"time"

	"github.com/elastic/beats/libbeat/outputs"
	"github.com/elastic/beats/libbeat/outputs/transport"

	"github.com/elastic/beats/heartbeat/monitors"
)

type Config struct {
	Name string `config:"name"`

	// check all ports if host does not contain port
	Ports     []uint16            `config:"ports"`
	Interface map[string][]string `config:"interface" validate:"required"`

	Mode monitors.IPSettings `config:",inline"`

	Socks5 transport.ProxyConfig `config:",inline"`

	// configure tls
	TLS *outputs.TLSConfig `config:"ssl"`

	Timeout time.Duration `config:"timeout"`

	// validate connection
	SendString    string `config:"check.send"`
	ReceiveString string `config:"check.receive"`

	// dns
	Dns transport.Dns `config:"dns"`
}

var DefaultConfig = Config{
	Name:    "tcp",
	Timeout: 16 * time.Second,
	Mode:    monitors.DefaultIPSettings,
	Dns:     transport.DefaultDnsSet,
}

func (c *Config) Validate() error {
	if c.Socks5.URL != "" {
		if c.Mode.Mode != monitors.PingAny && !c.Socks5.LocalResolve {
			return errors.New("ping all ips only supported if proxy_use_local_resolver is enabled`")
		}
	}

	return nil
}
