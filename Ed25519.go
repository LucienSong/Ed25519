package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gbrlsnchs/jwt"
	"golang.org/x/crypto/ed25519"
)

func genPayload(pub string) string {

	t := time.Now().Unix() + 10
	pl := fmt.Sprintf(`{"iat": %d,"key":"%s"}`, t, pub)

	return pl
}

func signature(pub, sec string) string {

	// Generate Key from seed
	k := ed25519.NewKeyFromSeed([]byte(sec))
	key := jwt.Ed25519PrivateKey(k)
	ed := jwt.NewEd25519(key)

	// Generate Header
	header := []byte(`{
		"alg": "Ed25519",
		"typ": "JWT"
	  }`)

	buffer := new(bytes.Buffer)
	json.Compact(buffer, header)
	jwtHeader := base64.URLEncoding.EncodeToString(buffer.Bytes())
	jh := strings.TrimRight(jwtHeader, "=")

	// Generate Payload
	plstr := genPayload(pub)
	payload := []byte(plstr)

	buffer2 := new(bytes.Buffer)
	json.Compact(buffer2, payload)
	jwtPayload := base64.URLEncoding.EncodeToString(buffer2.Bytes())
	jp := strings.TrimRight(jwtPayload, "=")

	// Generate Header + Payload
	s := strings.Join([]string{jh, jp}, ".")
	hp := []byte(s)

	// Generate Signature
	tk, err := ed.Sign(hp)
	if err != nil {
		log.Printf("Err: \n%v\n", err)
	}

	// Generate Token
	sig := strings.TrimRight(base64.URLEncoding.EncodeToString(tk), "=")
	token := strings.Join([]string{jh, jp, sig}, ".")

	return token
}

func main() {
	sec := "CNC88888888888888888888888888888"
	pub := "cnc6666666666666"

	sig := signature(pub, sec)

	log.Printf("Token:\n%s\n", sig)
}
