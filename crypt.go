//Crypto and hash wrapper
package crypt

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	//	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"log"
	"math/big"
)

//Simple crc32 checksum
func Crc32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

//Get key from passphrase by sha256
func PassKey(passphrase string) [32]byte {
	return sha256.Sum256([]byte(passphrase))
}

//Get random 32 bytes
func RandKey() [32]byte {
	var randNum [32]byte
	io.ReadFull(rand.Reader, randNum[:])
	return randNum
}

///Simmetric AES encoding
type AES struct {
	Key []byte
}

func (coder *AES) GenKeys() error {
	rnd := RandKey()
	coder.Key = rnd[:]
	return nil
}

func (coder *AES) Enc(msg []byte) ([]byte, error) {
	if len(coder.Key) != 32 {
		return msg, errors.New("Wrong AES key length")
	}
	block, err := aes.NewCipher(coder.Key)
	if err != nil {
		log.Println("AES encoding fail", err)
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {

	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))

	return ciphertext, err
}

//Simetric AES Decoding
func (coder *AES) Dec(ciphertext []byte) ([]byte, error) {
	if len(coder.Key) != 32 {
		return ciphertext, errors.New("Wrong AES key length")
	}
	block, err := aes.NewCipher(coder.Key)

	iv := ciphertext[:aes.BlockSize]
	code := ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	msg := make([]byte, len(code))
	cfb.XORKeyStream(msg, code)

	return msg, err
}

///RSA assimetric
type RSA struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

//Generate RSA keys
func (coder *RSA) GenKeys() error {
	var err error
	coder.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		log.Println(err)
	}
	coder.PublicKey = &coder.PrivateKey.PublicKey
	return err
}

func (coder *RSA) Keys() (*rsa.PrivateKey, *rsa.PublicKey) {
	return coder.PrivateKey, coder.PublicKey
}

func BytesToPubKey(key []byte) (*rsa.PublicKey, error) {
	pubKey := new(rsa.PublicKey)
	err := json.Unmarshal(key, pubKey)
	return pubKey, err
}

func PubKeyToBytes(key *rsa.PublicKey) []byte {
	bytes, _ := json.Marshal(key)
	return bytes
}

//Encrypt RSA
func (coder *RSA) Enc(msg []byte) ([]byte, error) {
	_, pubKey := coder.Keys()
	if pubKey == nil {
		return msg, errors.New("RSA PublicKey Not found!")
	}

	label := []byte("")
	hash := sha256.New()

	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, msg, label)

	if err != nil {
		log.Println(err)
	}

	return ciphertext, err
}

//Decrypt RSA
func (coder *RSA) Dec(code []byte) ([]byte, error) {
	privKey, _ := coder.Keys()
	if privKey == nil {
		return code, errors.New("RSA PrivateKey Not found!")
	}

	label := []byte("")
	hash := sha256.New()
	plainText, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, code, label)

	if err != nil {
		log.Println(err)
	}

	return plainText, err
}

//Get Signature
func (coder *RSA) Sign(data []byte) ([]byte, error) {
	privKey, _ := coder.Keys()
	if privKey == nil {
		return []byte{}, errors.New("RSA PrivateKey Not found!")
	}

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(data)
	hashed := pssh.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privKey, newhash, hashed, &opts)

	if err != nil {
		log.Println(err)
	}

	return signature, err
}

//Verify signature
func (coder *RSA) Verify(data, sign []byte) bool {
	_, pubKey := coder.Keys()
	if pubKey == nil {
		log.Println("RSA PublicKey Not found!")
		return false
	}

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(data)
	hashed := pssh.Sum(nil)

	err := rsa.VerifyPSS(pubKey, newhash, hashed, sign, &opts)

	if err != nil {
		return false
	} else {
		return true
	}
}

//Elliptic curve chipher
type Elliptic struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

func (coder *Elliptic) GenKeys() error {
	var err error
	curve := elliptic.P256()
	coder.PrivateKey, err = ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		log.Fatal(err)
	}
	coder.PublicKey = &coder.PrivateKey.PublicKey
	return err
}

func (coder *Elliptic) Keys() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	//	log.Println("keys", coder.PrivateKey, &coder.PrivateKey.PublicKey)
	return coder.PrivateKey, &coder.PrivateKey.PublicKey
}

type EllipticSign struct {
	r, s big.Int
}

func (sign *EllipticSign) Bytes() []byte {
	signature := sign.r.Bytes()
	signature = append(signature, sign.s.Bytes()...)
	return signature
}

func ellipticSign(sign []byte) *EllipticSign {
	sg := new(EllipticSign)

	l := len(sign) / 2
	sg.r.SetBytes(sign[:l])
	sg.s.SetBytes(sign[l:])

	return sg
}

func (coder *Elliptic) Sign(data []byte) ([]byte, error) {
	privKey, _ := coder.Keys()
	if privKey == nil {
		return []byte{}, errors.New("Elliptic PrivateKey Not found!")
	}

	hasher := md5.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	//	log.Println("Sign hash ", hash)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)

	//	log.Println("Sign point ", s.Bytes(), r.Bytes())

	if err != nil {
		log.Println(err)
	}

	signature := EllipticSign{*r, *s}

	return signature.Bytes(), err
}

func (coder *Elliptic) Verify(data, sign []byte) bool {
	_, pubKey := coder.Keys()
	if pubKey == nil {
		log.Println("Elliptic PublicKey Not found!")
		return false
	}

	ell_sign := ellipticSign(sign)

	hasher := md5.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	//	log.Println("Ver point ", s.Bytes(), r.Bytes())

	status := ecdsa.Verify(pubKey, hash, &ell_sign.r, &ell_sign.s)

	return status
}

func (coder *Elliptic) Enc(data []byte) []byte {
	//TODO
	return data
}

func (coder *Elliptic) Dec(data []byte) []byte {
	//TODO
	return data
}
