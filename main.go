package main

import "C"
import (
	"crypto/rand"
	"encoding/base64"
	"envelope/pkcs12"
	"envelope/sm2"
	"envelope/sm4"
	"fmt"
	"log"
	mrand "math/rand"
	"strconv"
	"strings"
	"time"
)

func main() {

	msg := "hello,world"

	publicKey, err := pkcs12.GetPublicKeyFromSM2File("D:\\Users\\test.cer")
	if err != nil {
		log.Fatalln(err)
	}

	encrypt, err := sm2.Encrypt(rand.Reader, publicKey, []byte(msg))
	if err != nil {
		log.Fatal(err)
	}
	eMsg := base64.StdEncoding.EncodeToString(encrypt)
	fmt.Println(eMsg)
	privateKey, err := pkcs12.GetPrivateKeyFromSm2File("D:\\Users\\test_gm.sm2", "cfca1234")
	if err != nil {
		log.Fatal(err)
	}
	decodeString, err := base64.StdEncoding.DecodeString("MHoCIQC4idvCHSf59TQxsrWc8lxylLYt5xBrBQWG5qWOk1qEugIhAN/g2lmSkWxCK0Uk6AH7T/OoEiWgd93HWorQec5nzBrSBCBEhbMtJxumKkNsxKcRtPiD7NPE3ZiVJOTXFuGq5BEeRAQQDiBgQApm0f9zW2sii9DL0A==")

	decrypt, err := sm2.Decrypt(privateKey, decodeString)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(decrypt))

}
//export PrintHello
func PrintHello(Input *C.char, output **C.char) int32 {
	//*output = C.CString(fmt.Sprintf("From DLL: Hello, %s!\n", C.GoString(Input)))
	publicKey, err := pkcs12.GetPublicKeyFromSM2File(C.GoString(Input))
	*output = C.CString(publicKey.Y.String())
	if err != nil {
		log.Fatalln(err)
	}
	return int32(len(C.GoString(*output)))
}

//export GetSymmetricCipher
func GetSymmetricCipher() *C.char {
	var sb strings.Builder
	mrand.Seed(time.Now().UnixNano())
	for i := 0; i < 16; i++ {
		sb.WriteString(strconv.FormatInt(int64(mrand.Intn(16)),16))
	}
	return C.CString(sb.String())
}

//export EncryptDataToCMSEnvelope
func EncryptDataToCMSEnvelope(path,msg *C.char,cipherMsg,envelope **C.char) int {
	filePath := C.GoString(path)
	symmetricCipher := GetSymmetricCipher()
	ret := SymEncryptData(msg,symmetricCipher,cipherMsg)
	if ret == 0 {
		return 0
	}

	publicKey, err := pkcs12.GetPublicKeyFromSM2File(filePath)
	if err != nil {
		return 0
	}

	encrypt, err := sm2.Encrypt(rand.Reader, publicKey, []byte("02|"+C.GoString(symmetricCipher)))
	if err != nil {
		return 0
	}
	res := base64.StdEncoding.EncodeToString(encrypt)
	*envelope = C.CString(res)
	return 1
}

/**
path: 私钥文件地址
pw: 私钥密码
msg: 对称加密密文（base64）
envelope: 数字信封
Output: 明文
 */
//export DecryptDataFromCMSEnvelope
func DecryptDataFromCMSEnvelope(path,pw,msg,envelope *C.char,Output **C.char) int {
	privateKey, err := pkcs12.GetPrivateKeyFromSm2File(C.GoString(path), C.GoString(pw))
	if err != nil {
		return 12
	}
	ebytes, err := base64.StdEncoding.DecodeString(C.GoString(envelope))
	if err != nil {
		return 13
	}
	decrypt, err := sm2.Decrypt(privateKey, ebytes)
	if err != nil {
		return 14
	}

	ret := SymDecryptData(msg, C.CString(string(decrypt)), Output)
	if ret != 1 {
		return 15
	}
	return 1
}

/**
对称加密
msg: 明文数据
cipherPlain: 对称密钥
 */
//export SymEncryptData
func SymEncryptData(msg,cipherPlain *C.char,output **C.char) int {
	c := C.GoString(cipherPlain)
	kdf := pkcs12.KDF([]byte(c))
	iv := make([]byte,16)
	key := make([]byte,16)
	copy(iv,kdf[:16])
	copy(key,kdf[16:])
	sm4Cipher := sm4.Init(iv, key)

	out, err := sm4Cipher.Sm4Cbc([]byte(C.GoString(msg)), true)
	if err != nil {
		return 0
	}

	*output = C.CString(base64.StdEncoding.EncodeToString(out))
	return 1
}
/**
msg: 对称加密的密文(base64)
cipherPlain: 对称密钥
 */
//export SymDecryptData
func SymDecryptData(msg,cipherPlain *C.char,output **C.char) int {
	c := C.GoString(cipherPlain)
	cs := strings.Split(c, "|")
	if cs[0] != "02" {
		return 0
	}
	kdf := pkcs12.KDF([]byte(cs[1]))
	iv := make([]byte,16)
	key := make([]byte,16)
	copy(iv,kdf[:16])
	copy(key,kdf[16:])
	sm4Cipher := sm4.Init(iv, key)

	m, err := base64.StdEncoding.DecodeString(C.GoString(msg))
	if err != nil {
		return 0
	}
	out, err := sm4Cipher.Sm4Cbc(m, false)
	if err != nil {
		return 0
	}

	*output = C.CString(string(out))
	return 1
}