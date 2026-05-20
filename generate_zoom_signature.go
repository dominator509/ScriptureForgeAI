package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

func main() {
	body := `{"event":"endpoint.url_validation","payload":{"plainToken":"qawsedrftgyhujikolp"}}`
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	zoomSecretToken := "zoom-webhook-secret"

	message := fmt.Sprintf("v0:%s:%s", timestamp, body)
	mac := hmac.New(sha256.New, []byte(zoomSecretToken))
	mac.Write([]byte(message))
	expectedSignature := "v0=" + hex.EncodeToString(mac.Sum(nil))

	fmt.Printf("%s|%s\n", timestamp, expectedSignature)
}
