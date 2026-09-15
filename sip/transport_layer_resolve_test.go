package sip

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// A carrier that publishes SRV records but has no address record of its own.
// This is a normal RFC 3263 deployment and the case resolveAddr used to get
// wrong: it ran net.ParseIP over the SRV target, which is a hostname, so the
// resolved IP was nil with no error reported.
func TestResolveAddrSRVOnlyHost(t *testing.T) {
	zone := dnsZone{
		"carrier.example":            {}, // no A/AAAA -- forces the SRV path
		"_sip._udp.carrier.example":  {srv: []dnsSRV{{target: "edge.carrier.example", port: 5060}}},
		"_sip._tcp.carrier.example":  {srv: []dnsSRV{{target: "edge.carrier.example", port: 5060}}},
		"_sips._tcp.carrier.example": {srv: []dnsSRV{{target: "edge.carrier.example", port: 5061}}},
		"edge.carrier.example":       {a: []string{"192.0.2.10"}},
	}

	for _, tt := range []struct {
		network   string
		wantQuery string
		wantAddr  string
	}{
		{network: "udp", wantQuery: "_sip._udp.carrier.example", wantAddr: "192.0.2.10:5060"},
		{network: "tcp", wantQuery: "_sip._tcp.carrier.example", wantAddr: "192.0.2.10:5060"},
		// TLS runs over TCP, so the service label is _sips._tcp. Querying
		// _sip._tcp here would return the cleartext port.
		{network: "tls", wantQuery: "_sips._tcp.carrier.example", wantAddr: "192.0.2.10:5061"},
	} {
		t.Run(tt.network, func(t *testing.T) {
			dns := startDNS(t, zone)
			l := NewTransportLayer(dns.resolver(), NewParser(), nil)

			addr := Addr{}
			err := l.resolveAddr(context.Background(), tt.network, "carrier.example", &addr)
			require.NoError(t, err)

			require.NotNil(t, addr.IP, "a nil IP renders as \":<port>\", which dials the local host")
			require.Equal(t, tt.wantAddr, addr.String())
			require.Contains(t, dns.queried(), tt.wantQuery)
		})
	}
}

// A host with an address record must not trigger an SRV lookup, and must leave
// the port alone so the caller's URI port or transport default still applies.
func TestResolveAddrPrefersAddressRecord(t *testing.T) {
	zone := dnsZone{
		"carrier.example":            {a: []string{"192.0.2.20"}},
		"_sips._tcp.carrier.example": {srv: []dnsSRV{{target: "edge.carrier.example", port: 5061}}},
		"edge.carrier.example":       {a: []string{"192.0.2.10"}},
	}

	dns := startDNS(t, zone)
	l := NewTransportLayer(dns.resolver(), NewParser(), nil)

	addr := Addr{Port: 5080}
	require.NoError(t, l.resolveAddr(context.Background(), "tls", "carrier.example", &addr))

	require.Equal(t, "192.0.2.20:5080", addr.String())
	for _, q := range dns.queried() {
		require.NotContains(t, q, "_sips._tcp", "SRV must not be consulted when an address record exists")
	}
}

func TestResolveAddrPrefersIPv4(t *testing.T) {
	zone := dnsZone{
		"carrier.example": {a: []string{"192.0.2.30"}, aaaa: []string{"2001:db8::1"}},
	}

	dns := startDNS(t, zone)
	l := NewTransportLayer(dns.resolver(), NewParser(), nil)

	addr := Addr{Port: 5060}
	require.NoError(t, l.resolveAddr(context.Background(), "udp", "carrier.example", &addr))
	require.Equal(t, "192.0.2.30:5060", addr.String())
}

// Every failure must be reported as an error. Returning a nil IP with a nil
// error is what made the original bug invisible to callers.
func TestResolveAddrErrorsRatherThanReturningNilIP(t *testing.T) {
	for _, tt := range []struct {
		name    string
		zone    dnsZone
		wantErr string
	}{
		{
			name:    "no address and no SRV records",
			zone:    dnsZone{"carrier.example": {}},
			wantErr: "fail to resolve target",
		},
		{
			name: "SRV target does not resolve",
			zone: dnsZone{
				"carrier.example":           {},
				"_sip._udp.carrier.example": {srv: []dnsSRV{{target: "missing.carrier.example", port: 5060}}},
			},
			wantErr: "resolve SRV target",
		},
		{
			name: "SRV target exists but has no address record",
			zone: dnsZone{
				"carrier.example":           {},
				"_sip._udp.carrier.example": {srv: []dnsSRV{{target: "edge.carrier.example", port: 5060}}},
				"edge.carrier.example":      {},
			},
			wantErr: "resolve SRV target",
		},
		{
			// RFC 2782: a "." target advertises that the service is not offered.
			name: "SRV root target",
			zone: dnsZone{
				"carrier.example":           {},
				"_sip._udp.carrier.example": {srv: []dnsSRV{{target: ".", port: 0}}},
			},
			wantErr: "not available",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dns := startDNS(t, tt.zone)
			l := NewTransportLayer(dns.resolver(), NewParser(), nil)

			addr := Addr{}
			err := l.resolveAddr(context.Background(), "udp", "carrier.example", &addr)

			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
			require.Nil(t, addr.IP, "a failed resolution must not leave a partial address behind")
		})
	}
}

// --- test DNS server --------------------------------------------------------
//
// Enough of RFC 1035 to answer the A/AAAA/SRV queries the Go resolver makes,
// so these tests need no live DNS and no external fixture.

type dnsSRV struct {
	target string
	port   int
}

type dnsRecords struct {
	a    []string
	aaaa []string
	srv  []dnsSRV
}

type dnsZone map[string]dnsRecords

type testDNS struct {
	addr string

	mu    sync.Mutex
	names []string
}

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	dnsTypeSRV  = 33
)

func startDNS(t *testing.T, zone dnsZone) *testDNS {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	d := &testDNS{addr: conn.LocalAddr().String()}

	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return // closed by cleanup
			}
			if resp := d.respond(buf[:n], zone); resp != nil {
				conn.WriteTo(resp, from)
			}
		}
	}()

	return d
}

func (d *testDNS) resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "udp", d.addr)
		},
	}
}

func (d *testDNS) queried() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.names...)
}

func (d *testDNS) respond(query []byte, zone dnsZone) []byte {
	if len(query) < 12 {
		return nil
	}
	name, qtype, end, ok := parseDNSQuestion(query)
	if !ok {
		return nil
	}

	d.mu.Lock()
	d.names = append(d.names, name)
	d.mu.Unlock()

	answers, rcode := zone.answer(name, qtype)

	resp := make([]byte, 0, 512)
	resp = append(resp, query[0], query[1]) // transaction ID
	resp = binary.BigEndian.AppendUint16(resp, 0x8180|uint16(rcode))
	resp = binary.BigEndian.AppendUint16(resp, 1)                    // QDCOUNT
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(answers))) // ANCOUNT
	resp = binary.BigEndian.AppendUint16(resp, 0)                    // NSCOUNT
	resp = binary.BigEndian.AppendUint16(resp, 0)                    // ARCOUNT
	resp = append(resp, query[12:end]...)                            // echo the question
	for _, a := range answers {
		resp = append(resp, a...)
	}
	return resp
}

// answer matches a query name against the zone, tolerating any search suffix
// the stub resolver appended. A known name with no matching record type yields
// NOERROR with no answers (NODATA); an unknown name yields NXDOMAIN.
func (z dnsZone) answer(name string, qtype uint16) ([][]byte, int) {
	for key, rec := range z {
		if name != key && !strings.HasPrefix(name, key+".") {
			continue
		}

		var out [][]byte
		switch qtype {
		case dnsTypeA:
			for _, ip := range rec.a {
				out = append(out, dnsRR(name, dnsTypeA, net.ParseIP(ip).To4()))
			}
		case dnsTypeAAAA:
			for _, ip := range rec.aaaa {
				out = append(out, dnsRR(name, dnsTypeAAAA, net.ParseIP(ip).To16()))
			}
		case dnsTypeSRV:
			for _, s := range rec.srv {
				rdata := make([]byte, 0, 16)
				rdata = binary.BigEndian.AppendUint16(rdata, 1) // priority
				rdata = binary.BigEndian.AppendUint16(rdata, 1) // weight
				rdata = binary.BigEndian.AppendUint16(rdata, uint16(s.port))
				rdata = append(rdata, encodeDNSName(s.target)...)
				out = append(out, dnsRR(name, dnsTypeSRV, rdata))
			}
		}
		return out, 0
	}
	return nil, 3 // NXDOMAIN
}

func dnsRR(name string, rrtype uint16, rdata []byte) []byte {
	rr := encodeDNSName(name)
	rr = binary.BigEndian.AppendUint16(rr, rrtype)
	rr = binary.BigEndian.AppendUint16(rr, 1)  // class IN
	rr = binary.BigEndian.AppendUint32(rr, 60) // TTL
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(rdata)))
	return append(rr, rdata...)
}

func encodeDNSName(name string) []byte {
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// parseDNSQuestion returns the query name, its type, and the offset just past
// the question section.
func parseDNSQuestion(msg []byte) (name string, qtype uint16, end int, ok bool) {
	var labels []string
	i := 12
	for i < len(msg) {
		n := int(msg[i])
		i++
		if n == 0 {
			break
		}
		if i+n > len(msg) {
			return "", 0, 0, false
		}
		labels = append(labels, string(msg[i:i+n]))
		i += n
	}
	if i+4 > len(msg) {
		return "", 0, 0, false
	}
	return strings.Join(labels, "."), binary.BigEndian.Uint16(msg[i : i+2]), i + 4, true
}
