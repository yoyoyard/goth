package apple

import (
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yoyoyard/goth"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientId(), os.Getenv("APPLE_KEY"))
	a.Equal(p.Secret(), os.Getenv("APPLE_SECRET"))
	a.Equal(p.RedirectURL(), "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "appleid.apple.com/auth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://appleid.apple.com/auth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*Session)
	a.Equal(s.AuthURL, "https://appleid.apple.com/auth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *Provider {
	return New(os.Getenv("APPLE_KEY"), os.Getenv("APPLE_SECRET"), "/foo", nil)
}

func TestMakeSecret(t *testing.T) {
	a := assert.New(t)

	iat := 1570636633
	ss, err := MakeSecret(SecretParams{
		PKCS8PrivateKey: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPALVklHT2n9FNxeP
c1+TCP+Ep7YOU7T9KB5MTVpjL1ShRANCAATXAbDMQ/URATKRoSIFMkwetLH/M2S4
nNFzkp23qt9IJDivieB/BBJct1UvhoICg5eZDhSR+x7UH3Uhog8qgoIC
-----END PRIVATE KEY-----`, // example
		TeamId:   "TK...",
		KeyId:    "<keyId>",
		ClientId: "<clientId>",
		Iat:      iat,
		Exp:      iat + 15777000,
	})
	a.NoError(err)
	a.NotZero(ss)
	//fmt.Printf("signed secret: %s", *ss)
}

func TestAuthorize(t *testing.T) {
	ss := "" // a value from MakeSecret
	if ss == "" {
		t.Skip()
	}

	a := assert.New(t)

	client := http.DefaultClient
	p := New(
		"<clientId>",
		ss,
		"https://example-app.com/redirect",
		client,
		"name", "email")
	session, _ := p.BeginAuth("test_state")

	_, err := session.Authorize(p, url.Values{
		"code": []string{"<authorization code from successful authentication>"},
	})
	if err != nil {
		errStr := err.Error()
		a.Fail(errStr)
	}
}
