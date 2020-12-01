package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	capubFile     = flag.String("capubFile", "../certs/tls-ca.crt", "Path to input Public CA key")
	caprivFile    = flag.String("caprivFile", "../certs/tls-ca.key", "Path to input Private key to sign the JWT")
	clientpubCert = flag.String("clientpubCert", "../certs/clientjwt.crt", "Path to public certificate to create X5T")
	tbh           = flag.String("tbh", "dBPwPU6FpL1xgsUfqxZOMe4fXkR1UINjx3DK2AkNwSs", "TBH value to use")
)

const ()

type CBF struct {
	TBH string `json:"tbh,omitempty"`
	X5T string `json:"x5t#S256,omitempty"`
}

type CustomClaimsExample struct {
	*jwt.StandardClaims
	CBF `json:"cbf"`
}

func main() {

	flag.Parse()

	dat, err := ioutil.ReadFile(*clientpubCert)
	if err != nil {
		log.Fatalf("Failed to read PEM File: %v", err)
	}
	block, _ := pem.Decode([]byte(dat))
	if block == nil {
		log.Fatalf("failed to parse certificate PEM")
	}
	pub, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to ParseCertificate")
	}

	h := sha256.New()
	h.Write(pub.Raw)

	f := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	//*

	cadat, err := ioutil.ReadFile(*capubFile)
	if err != nil {
		log.Fatalf("Failed to read PEM File: %v", err)
	}
	cablock, _ := pem.Decode([]byte(cadat))
	if cablock == nil {
		log.Fatalf("failed to parse certificate PEM")
	}
	capub, err := x509.ParseCertificate(cablock.Bytes)
	if err != nil {
		log.Fatalf("failed to ParseCertificate")
	}

	keyData, err := ioutil.ReadFile(*caprivFile)
	if err != nil {
		log.Fatalf("Error reading private key: %v", err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
	}

	c := CBF{
		TBH: *tbh,
		X5T: f,
	}

	claims := &CustomClaimsExample{
		&jwt.StandardClaims{
			Issuer:    "https://myissuer",
			Audience:  "https://foo.bar",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour * 24 * 356).Unix(),
		},
		c,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = fmt.Sprintf("%d", capub.SerialNumber)
	ss, err := token.SignedString(key)
	if err != nil {
		log.Fatalf("Error reading key: %v", err)
	}

	log.Println(ss)
}
