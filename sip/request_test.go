package sip

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Shape of a real 200 OK from a FreeSWITCH behind a double record-routing
// proxy (internal hop first, public TLS hop last) with a private UDP Contact.
func recordRoutedDialog(t *testing.T) (*Request, *Response) {
	t.Helper()
	rawInv := strings.Join([]string{
		"INVITE sips:7002024535@carrier.example.com SIP/2.0",
		"Via: SIP/2.0/TLS 198.51.100.1:48425;branch=z9hG4bK.abc",
		"From: <sip:us.example.com>;tag=ftag",
		"To: <sips:7002024535@carrier.example.com>",
		"Call-ID: call-1",
		"CSeq: 1 INVITE",
		"Contact: <sip:198.51.100.1:5061;transport=tls>",
		"Content-Length: 0",
		"", "",
	}, "\r\n")
	m, err := ParseMessage([]byte(rawInv))
	require.NoError(t, err)
	inv := m.(*Request)
	inv.SetTransport("TLS")
	inv.SetDestination("203.0.113.10:5061")

	raw := strings.Join([]string{
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/TLS 198.51.100.1:48425;branch=z9hG4bK.abc",
		"Record-Route: <sip:203.0.113.10:5050;r2=on;lr;to-net=internal>",
		"Record-Route: <sip:203.0.113.10:5061;transport=tls;r2=on;lr;from-net=public>",
		"From: <sip:us.example.com>;tag=ftag",
		"To: <sips:7002024535@carrier.example.com>;tag=ttag",
		"Call-ID: call-1",
		"CSeq: 1 INVITE",
		"Contact: <sip:7002024535@10.0.0.5:5060;transport=udp>",
		"Content-Length: 0",
		"", "",
	}, "\r\n")
	msg, err := ParseMessage([]byte(raw))
	require.NoError(t, err)
	return inv, msg.(*Response)
}

// routeHops returns host:port of each Route header in order. URI param order
// is not stable across re-serialization, so compare hops, not raw strings.
func routeHops(t *testing.T, r *Request) []string {
	t.Helper()
	var out []string
	for _, h := range r.GetHeaders("Route") {
		var u Uri
		require.NoError(t, parseRouteAddress(h.Value(), &u))
		out = append(out, u.HostPort())
	}
	return out
}

func routeValues(r *Request) []string {
	var out []string
	for _, h := range r.GetHeaders("Route") {
		out = append(out, h.Value())
	}
	return out
}

func TestAckAndByeUseReversedRecordRouteAsRoute(t *testing.T) {
	inv, res := recordRoutedDialog(t)
	want := []string{"203.0.113.10:5061", "203.0.113.10:5050"}

	ack := NewAckRequest(inv, res, nil)
	assert.Equal(t, want, routeHops(t, ack))
	assert.Empty(t, ack.GetHeaders("Record-Route"), "Record-Route must not be echoed on ACK")
	assert.Equal(t, "10.0.0.5", ack.Recipient.Host, "request-URI is the remote target")

	bye := NewByeRequestUAC(inv, res, nil)
	assert.Equal(t, want, routeHops(t, bye))
	assert.Equal(t, "203.0.113.10:5061", bye.Destination(), "BYE goes to the top Route (public hop)")
}

func TestDialogRoutesSplitCommaJoinedRecordRoute(t *testing.T) {
	inv, res := recordRoutedDialog(t)
	for res.RemoveHeader("Record-Route") {
	}
	res.AppendHeader(NewHeader("Record-Route", `<sip:p1.example.com;lr>, "x,y" <sip:p2.example.com;lr>`))

	ack := NewAckRequest(inv, res, nil)
	assert.Equal(t, []string{`"x,y" <sip:p2.example.com;lr>`, "<sip:p1.example.com;lr>"}, routeValues(ack))
}

func TestDialogRoutesFallBackToInviteRoute(t *testing.T) {
	inv, res := recordRoutedDialog(t)
	for res.RemoveHeader("Record-Route") {
	}
	inv.AppendHeader(NewHeader("Route", "<sip:outbound-proxy.example.com;lr>"))

	assert.Equal(t, []string{"<sip:outbound-proxy.example.com;lr>"}, routeValues(NewAckRequest(inv, res, nil)))
	assert.Equal(t, []string{"<sip:outbound-proxy.example.com;lr>"}, routeValues(NewByeRequestUAC(inv, res, nil)))
}

func TestNon2xxAckKeepsInviteRoute(t *testing.T) {
	inv, res := recordRoutedDialog(t)
	inv.AppendHeader(NewHeader("Route", "<sip:outbound-proxy.example.com;lr>"))
	res.StatusCode = StatusBusyHere

	ack := newAckRequestNon2xx(inv, res, nil)
	assert.Equal(t, []string{"<sip:outbound-proxy.example.com;lr>"}, routeValues(ack))
}
