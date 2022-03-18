/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm2

// reference to ecdsa
import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"envelope/sm3"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	xasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"io"
	"math/big"
)

var (
	default_uid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	C1C3C2      = 0
	C1C2C3      = 1
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

type sm2Signature struct {
	R, S *big.Int
}


// The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

var errZeroParam = errors.New("zero parameter")
var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)

// sign format = 30 + len(z) + 02 + len(r) + r + 02 + len(s) + s, z being what follows its size, ie 02+len(r)+r+02+len(s)+s
func (priv *PrivateKey) Sign(random io.Reader, msg []byte, signer crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sm2Sign(priv, msg, nil, random)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sm2Signature{r, s})
}

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {
	var sm2Sign sm2Signature
	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return false
	}
	return Sm2Verify(pub, msg, default_uid, sm2Sign.R, sm2Sign.S)
}

func (pub *PublicKey) Sm3Digest(msg, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = default_uid
	}

	za, err := ZA(pub, uid)
	if err != nil {
		return nil, err
	}

	e, err := msgHash(za, msg)
	if err != nil {
		return nil, err
	}

	return e.Bytes(), nil
}
func Sm2Sign(priv *PrivateKey, msg, uid []byte, random io.Reader) (r, s *big.Int, err error) {
	digest, err := priv.PublicKey.Sm3Digest(msg, uid)
	if err != nil {
		return nil, nil, err
	}
	e := new(big.Int).SetBytes(digest)
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	var k *big.Int
	for { // 调整算法细节以实现SM2
		for {
			k, err = randFieldElement(c, random)
			if err != nil {
				r = nil
				return
			}
			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}

		}
		rD := new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, rD)

		d1 := new(big.Int).Add(priv.D, one)
		// (1+priv.D)-1
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}
	return
}
func Sm2Verify(pub *PublicKey, msg, uid []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N
	one := new(big.Int).SetInt64(1)
	if r.Cmp(one) < 0 || s.Cmp(one) < 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	if len(uid) == 0 {
		uid = default_uid
	}
	za, err := ZA(pub, uid)
	if err != nil {
		return false
	}
	e, err := msgHash(za, msg)
	if err != nil {
		return false
	}
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}
	var x *big.Int
	x1, y1 := c.ScalarBaseMult(s.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, _ = c.Add(x1, y1, x2, y2)

	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

/*
 * sm2密文结构如下:
 *  x
 *  y
 *  hash
 *  CipherText
 */

func msgHash(za, msg []byte) (*big.Int, error) {
	e := sm3.New()
	e.Write(za)
	e.Write(msg)
	return new(big.Int).SetBytes(e.Sum(nil)[:32]), nil
}

// ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func ZA(pub *PublicKey, uid []byte) ([]byte, error) {
	za := sm3.New()
	uidLen := len(uid)
	if uidLen >= 8192 {
		return []byte{}, errors.New("SM2: uid too large")
	}
	Entla := uint16(8 * uidLen)
	za.Write([]byte{byte((Entla >> 8) & 0xFF)})
	za.Write([]byte{byte(Entla & 0xFF)})
	if uidLen > 0 {
		za.Write(uid)
	}
	za.Write(sm2P256ToBig(&sm2P256.a).Bytes())
	za.Write(sm2P256.B.Bytes())
	za.Write(sm2P256.Gx.Bytes())
	za.Write(sm2P256.Gy.Bytes())

	xBuf := pub.X.Bytes()
	yBuf := pub.Y.Bytes()
	if n := len(xBuf); n < 32 {
		xBuf = append(zeroByteSlice()[:32-n], xBuf...)
	}
	if n := len(yBuf); n < 32 {
		yBuf = append(zeroByteSlice()[:32-n], yBuf...)
	}
	za.Write(xBuf)
	za.Write(yBuf)
	return za.Sum(nil)[:32], nil
}

// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

/*
sm2加密，返回asn.1编码格式的密文内容

*/
func Encrypt(random io.Reader, pub *PublicKey, msg []byte) ([]byte, error) {
	curve := pub.Curve
	msgLen := len(msg)
	if msgLen == 0 {
		return nil, nil
	}

	//A3, requirement is to check if h*P is infinite point, h is 1
	if pub.X.Sign() == 0 && pub.Y.Sign() == 0 {
		return nil, errors.New("SM2: invalid public key")
	}

	for {
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}
		//A2, calculate C1 = k * G
		x1, y1 := curve.ScalarBaseMult(k.Bytes())

		//A4, calculate k * P (point of Public Key)
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

		//A5, calculate t=KDF(x2||y2, klen)
		var kdfCount int = 0
		t, success := kdf(msgLen, append(toBytes(curve, x2), toBytes(curve, y2)...))
		if !success {
			kdfCount++
			// 最大尝试100次
			if kdfCount > 100 {
				return nil, fmt.Errorf("SM2: A5, failed to calculate valid t, tried %v times", kdfCount)
			}
			continue
		}

		//A6, C2 = M ^ t;
		c2 := make([]byte, msgLen)
		for i := 0; i < msgLen; i++ {
			c2[i] = msg[i] ^ t[i]
		}

		//A7, C3 = hash(x2||M||y2)
		md := sm3.New()
		md.Write(toBytes(curve, x2))
		md.Write(msg)
		md.Write(toBytes(curve, y2))
		c3 := md.Sum(nil)

		return mashalASN1Ciphertext(x1, y1, c2, c3)
	}
}
/**
sm2 解密，针对asn1格式进行解密
 */
func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, err
	}

	curve := priv.Curve
	x2, y2 := curve.ScalarMult(x1, y1, priv.D.Bytes())
	msgLen := len(c2)
	t, success := kdf(msgLen, append(toBytes(curve, x2), toBytes(curve, y2)...))
	if !success {
		return nil, errors.New("SM2: invalid cipher text")
	}

	//B5, calculate msg = c2 ^ t
	msg := make([]byte, msgLen)
	for i := 0; i < msgLen; i++ {
		msg[i] = c2[i] ^ t[i]
	}
	md := sm3.New()
	md.Write(toBytes(curve, x2))
	md.Write(msg)
	md.Write(toBytes(curve, y2))
	u := md.Sum(nil)
	for i := 0; i < sm3.Size; i++ {
		if c3[i] != u[i] {
			return nil, errors.New("SM2: invalid hash value")
		}
	}
	return msg, nil
}

func mashalASN1Ciphertext(x1, y1 *big.Int, c2, c3 []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(xasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(x1)
		b.AddASN1BigInt(y1)
		b.AddASN1OctetString(c3)
		b.AddASN1OctetString(c2)
	})
	return b.Bytes()
}
func unmarshalASN1Ciphertext(ciphertext []byte) (*big.Int, *big.Int, []byte, []byte, error) {
	var (
		x1, y1 = &big.Int{}, &big.Int{}
		c2, c3 []byte
		inner  cryptobyte.String
	)
	input := cryptobyte.String(ciphertext)
	if !input.ReadASN1(&inner, xasn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(x1) ||
		!inner.ReadASN1Integer(y1) ||
		!inner.ReadASN1Bytes(&c3, xasn1.OCTET_STRING) ||
		!inner.ReadASN1Bytes(&c2, xasn1.OCTET_STRING) ||
		!inner.Empty() {
		return nil, nil, nil, nil, errors.New("SM2: invalid asn1 format ciphertext")
	}
	return x1, y1, c2, c3, nil
}

// BigInt 转化为byte，若bytes小于32，则其后补零值
func toBytes(curve elliptic.Curve, value *big.Int) []byte {
	bytes := value.Bytes()
	byteLen := (curve.Params().BitSize + 7) >> 3
	if byteLen == len(bytes) {
		return bytes
	}
	result := make([]byte, byteLen)
	copy(result[byteLen-len(bytes):], bytes)
	return result
}
func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}

func kdf(length int, x ...[]byte) ([]byte, bool) {
	var c []byte

	ct := 1
	h := sm3.New()
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		for _, xx := range x {
			h.Write(xx)
		}
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func GenerateKey(random io.Reader) (*PrivateKey, error) {
	c := P256Sm2()
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(random, b)
	if err != nil {
		return nil, err
	}

	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, two)
	k.Mod(k, n)
	k.Add(k, one)
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

	return priv, nil
}

type zr struct {
	io.Reader
}

func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

func getLastBit(a *big.Int) uint {
	return a.Bit(0)
}


