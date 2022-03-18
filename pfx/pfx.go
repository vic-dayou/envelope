package pfx

import (
	"crypto/rsa"
	"crypto/x509"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
	"os"
)

func GetPrivateKeyFromPfxFile(file, password string) (*rsa.PrivateKey, error) {
	open, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	pfxData, err := ioutil.ReadAll(open)
	if err != nil {
		return nil, err
	}
	blocks, err := pkcs12.ToPEM(pfxData, password)
	if err != nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(blocks[0].Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
