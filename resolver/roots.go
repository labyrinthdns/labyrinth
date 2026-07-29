package resolver

// NameServer represents a DNS nameserver with its IP addresses.
type NameServer struct {
	Name string
	IPv4 string
	IPv6 string
}

// RootServers contains the 13 root DNS servers with IPv4 and IPv6 addresses.
var RootServers = []NameServer{
	{Name: "a.root-servers.net", IPv4: "198.41.0.4", IPv6: "2001:503:ba3e::2:30"},
	{Name: "b.root-servers.net", IPv4: "170.247.170.2", IPv6: "2801:1b8:10::b"},
	{Name: "c.root-servers.net", IPv4: "192.33.4.12", IPv6: "2001:500:2::c"},
	{Name: "d.root-servers.net", IPv4: "199.7.91.13", IPv6: "2001:500:2d::d"},
	{Name: "e.root-servers.net", IPv4: "192.203.230.10", IPv6: "2001:500:a8::e"},
	{Name: "f.root-servers.net", IPv4: "192.5.5.241", IPv6: "2001:500:2f::f"},
	{Name: "g.root-servers.net", IPv4: "192.112.36.4", IPv6: "2001:500:12::d0d"},
	{Name: "h.root-servers.net", IPv4: "198.97.190.53", IPv6: "2001:500:1::53"},
	{Name: "i.root-servers.net", IPv4: "192.36.148.17", IPv6: "2001:7fe::53"},
	{Name: "j.root-servers.net", IPv4: "192.58.128.30", IPv6: "2001:503:c27::2:30"},
	{Name: "k.root-servers.net", IPv4: "193.0.14.129", IPv6: "2001:7fd::1"},
	{Name: "l.root-servers.net", IPv4: "199.7.83.42", IPv6: "2001:500:9f::42"},
	{Name: "m.root-servers.net", IPv4: "202.12.27.33", IPv6: "2001:dc3::35"},
}
