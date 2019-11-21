package fitbit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yoyoyard/goth"
	"github.com/yoyoyard/goth/providers/fitbit"
)

func Test_ImplementsSession(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &fitbit.Session{}
	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &fitbit.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"
	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &fitbit.Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z","UserID":""}`)
}
