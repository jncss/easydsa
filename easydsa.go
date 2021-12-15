package easydsa

import (
	"bytes"
	"crypto/dsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"hash"
	"io/ioutil"
	"math/big"
)

// PrivateKey Private key
type PrivateKey dsa.PrivateKey

// PublicKey Public key
type PublicKey dsa.PublicKey
type ParameterSizes dsa.ParameterSizes

const (
	L1024N160 ParameterSizes = iota
	L2048N224
	L2048N256
	L3072N256
)

type HashType int

const (
	MD5 HashType = iota
	SHA1
	SHA256
	SHA512
)

type Signature struct {
	R, S big.Int
}

// Keys
func GenerateKey(sizes ParameterSizes) *PrivateKey {
	params := new(dsa.Parameters)
	dsa.GenerateParameters(params, rand.Reader, dsa.ParameterSizes(sizes))
	privateKey := new(dsa.PrivateKey)
	privateKey.PublicKey.Parameters = *params
	dsa.GenerateKey(privateKey, rand.Reader)

	return (*PrivateKey)(privateKey)
}

// Private key methods
func (privateKey *PrivateKey) MarshalPEM() string {
	asn1Bytes, _ := asn1.Marshal(*privateKey)
	var buf bytes.Buffer
	var pemkey = &pem.Block{Type: "PRIVATE KEY", Bytes: asn1Bytes}
	pem.Encode(&buf, pemkey)

	return buf.String()
}

func (privateKey *PrivateKey) UnmarshalPEM(PEM string) (*PrivateKey, error) {
	block, _ := pem.Decode([]byte(PEM))
	_, err := asn1.Unmarshal(block.Bytes, privateKey)

	return privateKey, err
}

func (privateKey *PrivateKey) Store(filename string) error {
	return ioutil.WriteFile(filename, []byte(privateKey.MarshalPEM()), 0600)
}

func (privateKey *PrivateKey) Load(filename string) (*PrivateKey, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	_, err = privateKey.UnmarshalPEM(string(data))
	if err != nil {
		return nil, err
	}

	return privateKey, err
}

// Public key methods
func (privateKey *PrivateKey) GetPublicKey() PublicKey {
	return (PublicKey)(privateKey.PublicKey)
}

func (publicKey *PublicKey) MarshalPEM() string {
	asn1Bytes, _ := asn1.Marshal(*publicKey)
	var buf bytes.Buffer
	var pemkey = &pem.Block{Type: "PUBLIC KEY", Bytes: asn1Bytes}
	pem.Encode(&buf, pemkey)

	return buf.String()
}

func (publicKey *PublicKey) UnmarshalPEM(PEM string) (*PublicKey, error) {
	block, _ := pem.Decode([]byte(PEM))
	_, err := asn1.Unmarshal(block.Bytes, publicKey)

	return publicKey, err
}

func (publicKey *PublicKey) Store(filename string) error {
	return ioutil.WriteFile(filename, []byte(publicKey.MarshalPEM()), 0644)
}

func (publicKey *PublicKey) Load(filename string) (*PublicKey, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	_, err = publicKey.UnmarshalPEM(string(data))
	if err != nil {
		return nil, err
	}

	return publicKey, err
}

// Signature
func (signature *Signature) Marshal() string {
	s := append(signature.R.Bytes(), signature.S.Bytes()...)
	return base64.StdEncoding.EncodeToString(s)
}

func (signature *Signature) Unmarshal(str string) (*Signature, error) {
	bytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	l := len(bytes) / 2
	signature.R.SetBytes(bytes[:l])
	signature.S.SetBytes(bytes[l:])

	return signature, nil
}

func (signature *Signature) Store(filename string) error {
	return ioutil.WriteFile(filename, []byte(signature.Marshal()), 0644)
}

func (signature *Signature) Load(filename string) (*Signature, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	_, err = signature.Unmarshal(string(data))
	if err != nil {
		return nil, err
	}

	return signature, err
}

// Sign
func (privateKey *PrivateKey) Sign(hashType HashType, bytes []byte) (*Signature, error) {
	var hash hash.Hash

	switch hashType {
	case MD5:
		hash = md5.New()
	case SHA1:
		hash = sha1.New()
	case SHA256:
		hash = sha256.New()
	case SHA512:
		hash = sha512.New()
	}

	hash.Write(bytes)
	signHash := hash.Sum(nil)

	r, s, err := dsa.Sign(rand.Reader, (*dsa.PrivateKey)(privateKey), signHash)
	if err != nil {
		return nil, err
	}

	return &Signature{*r, *s}, nil
}

func (privateKey *PrivateKey) SignString(hashType HashType, str string) (*Signature, error) {
	return privateKey.Sign(hashType, []byte(str))
}

func (privateKey *PrivateKey) SignFile(hashType HashType, filename string) (*Signature, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return privateKey.Sign(hashType, data)
}

// Verify
func (publicKey *PublicKey) Verify(hashType HashType, bytes []byte, signature *Signature) bool {
	var hash hash.Hash

	switch hashType {
	case MD5:
		hash = md5.New()
	case SHA1:
		hash = sha1.New()
	case SHA256:
		hash = sha256.New()
	case SHA512:
		hash = sha512.New()
	}

	hash.Write(bytes)
	signHash := hash.Sum(nil)

	return dsa.Verify((*dsa.PublicKey)(publicKey), signHash, &signature.R, &signature.S)
}

func (publicKey *PublicKey) VerifyString(hashType HashType, str string, signature *Signature) bool {
	return publicKey.Verify(hashType, []byte(str), signature)
}

func (publicKey *PublicKey) VerifyFile(hashType HashType, filename string, signature *Signature) (bool, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return false, err
	}

	return publicKey.Verify(hashType, data, signature), nil
}
