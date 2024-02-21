package sip

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAddressValueWithLR(t *testing.T) {
	address := "<sip:abc@127.0.0.1:5060;lr>"
	uri := Uri{
		Headers: HeaderParams{},
	}
	params := NewParams()

	_, err := ParseAddressValue(address, &uri, params)
	assert.Nil(t, err)
}

func TestParseAddressValue(t *testing.T) {
	address := "\"Bob\" <sips:bob:password@127.0.0.1:5060;user=phone>;tag=1234"

	uri := Uri{}
	params := NewParams()

	displayName, err := ParseAddressValue(address, &uri, params)

	assert.Nil(t, err)
	assert.Equal(t, "sips:bob:password@127.0.0.1:5060;user=phone", uri.String())
	assert.Equal(t, "tag=1234", params.String())

	assert.Equal(t, "Bob", displayName)
	assert.Equal(t, "bob", uri.User)
	assert.Equal(t, "password", uri.Password)
	assert.Equal(t, "127.0.0.1", uri.Host)
	assert.Equal(t, 5060, uri.Port)
	assert.Equal(t, true, uri.Encrypted)
	assert.Equal(t, false, uri.Wildcard)

	user, ok := uri.UriParams.Get("user")
	assert.True(t, ok)
	assert.Equal(t, 1, uri.UriParams.Length())
	assert.Equal(t, "phone", user)
}

// TODO
// func TestParseAddressMultiline(t *testing.T) {
// contact:
// 	+`Contact: "Mr. Watson" <sip:watson@worcester.bell-telephone.com>
// 	;q=0.7; expires=3600,
// 	"Mr. Watson" <mailto:watson@bell-telephone.com> ;q=0.1`
// }

func BenchmarkParseAddress(b *testing.B) {
	address := "\"Bob\" <sips:bob:password@127.0.0.1:5060;user=phone>;tag=1234"
	uri := Uri{}
	params := NewParams()

	for i := 0; i < b.N; i++ {
		displayName, err := ParseAddressValue(address, &uri, params)
		assert.Nil(b, err)
		assert.Equal(b, "Bob", displayName)
	}
}
