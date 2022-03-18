package pkcs12

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"envelope/sm2"
	"envelope/sm3"
	"envelope/sm4"
	"envelope/x509"
	"errors"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
	"log"
	"math/big"
	"os"
)

type smPdu struct {
	Version     int
	PrivContent privateKeyContent
	PubContent  publicKeyContent
}

type privateKeyContent struct {
	OID1    asn1.ObjectIdentifier // {1.2.156.10197.6.1.4.2.1} SM2_Data
	OID2    asn1.ObjectIdentifier // {1.2.156.10197.1.104} SM4_CBC
	Content asn1.RawValue
}

type publicKeyContent struct {
	OID     asn1.ObjectIdentifier // {1.2.156.10197.6.1.4.2.1} SM2_Data
	Content asn1.RawValue
}

func DecodeSm2(smData []byte, password string) (privateKey *sm2.PrivateKey, certificate *x509.Certificate, err error) {
	sm := new(smPdu)
	trailing, err := asn1.Unmarshal(smData, sm)
	if err != nil {
		return nil, nil, err
	}
	if len(trailing) != 0 {
		return nil, nil, errors.New("go-pkcs12: trailing data found")
	}

	dBytes := DecryptSm2Key(password, sm.PrivContent.Content.Bytes)
	if len(dBytes) == 0 {
		return nil, nil, errors.New("密码错误")
	}

	cer, err := x509.ParseCertificate(sm.PubContent.Content.Bytes)
	if err != nil {
		log.Fatal(err)
		return nil, nil, err
	}

	//pub := cer.PublicKey.(*ecdsa.PublicKey)
	pub := cer.PublicKey.(*sm2.PublicKey)
	priv := &sm2.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(dBytes),
	}
	return priv, cer, nil
}

/**
Key Derivation function (密钥导出函数)
	将密钥扩展到所需长度的密钥
**/
func KDF(z []byte) []byte {
	ct := []byte{0, 0, 0, 1}
	sm3 := sm3.New()
	sm3.Write(z)
	sm3.Write(ct)
	h := sm3.Sum(nil)
	return h
}

/*
	解密sm2私钥
*/
func DecryptSm2Key(password string, encryptedData []byte) []byte {
	if len(encryptedData) >= 32 && len(encryptedData) <= 64 {
		encoding := make([]byte, len(encryptedData), len(encryptedData))
		if len(encryptedData) != 32 && len(encryptedData) != 48 {
			base64.StdEncoding.Decode(encoding, encryptedData)
		}
		encoding = encryptedData

		h := KDF([]byte(password))

		iv := h[:16]
		key := h[16:]

		sm4 := sm4.Init(iv, key)
		out, err := sm4.Sm4Cbc(encoding, false)
		if err != nil {
			log.Fatal(err)
		}

		d := new(big.Int)
		d.SetBytes(out)
		return out
	}
	return nil
}

func GetPrivateKeyFromSm2File(file, password string) (*sm2.PrivateKey, error) {
	open, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	smData, err := ioutil.ReadAll(open)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(string(smData))
	if err != nil {
		return nil, err
	}

	privateKey, _, err := DecodeSm2(b, password)
	return privateKey, err
}

func GetPrivateKeyFromBytes(data []byte, ext, password string) (interface{}, error) {
	if ext == ".sm2" {
		b, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, err
		}
		privateKey, _, err := DecodeSm2(b, password)
		return privateKey, err
	} else if ext == ".pfx" {
		blocks, err := pkcs12.ToPEM(data, password)
		if err != nil {
			if errors.Is(err, pkcs12.ErrIncorrectPassword) {
				return nil, errors.New("密码错误")
			}
			log.Println(err)
			return nil, err
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(blocks[0].Bytes)
		if err != nil {
			return nil, err
		}
		return privateKey, nil
	} else {
		return nil, errors.New("文件格式错误")
	}
}


func GetPublicKeyFromSM2File(file string) (*sm2.PublicKey,error) {
	open, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	cerData, err := ioutil.ReadAll(open)
	block, _ := pem.Decode(cerData)

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil,err
	}

	publicKey := certificate.PublicKey.(*sm2.PublicKey)
	return publicKey,nil
}