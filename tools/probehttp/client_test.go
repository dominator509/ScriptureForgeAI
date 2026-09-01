package probehttp

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewClientDisablesAmbientProxyAndRedirects(t *testing.T) {
	client := NewClient(time.Second)
	if client.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}
	if err := client.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect error = %v, want %v", err, http.ErrUseLastResponse)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("probe transport must not honor ambient proxy settings")
	}
	if transport.DialContext == nil {
		t.Fatal("probe transport must validate destinations at dial time")
	}
}

func TestDialContextRejectsRestrictedLiteralDestinations(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1:443",
		"10.0.0.8:443",
		"169.254.169.254:80",
		"[::1]:443",
		"[fd00::8]:443",
	} {
		t.Run(address, func(t *testing.T) {
			_, err := dialContext(t.Context(), "tcp", address)
			if err == nil || !strings.Contains(err.Error(), "restricted") {
				t.Fatalf("dialContext(%q) error = %v, want restricted-destination error", address, err)
			}
		})
	}
}

func TestIsDeniedIPAllowsGlobalUnicast(t *testing.T) {
	if isDeniedIP([]byte{8, 8, 8, 8}) {
		t.Fatal("global unicast address was denied")
	}
	if !isDeniedIP([]byte{198, 51, 100, 8}) {
		t.Fatal("documentation address was allowed")
	}
}
