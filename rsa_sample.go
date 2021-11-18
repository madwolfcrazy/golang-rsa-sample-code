package fooobar

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

var privateKey string = `-----BEGIN PRIVATE KEY-----
MIIEpQIBAAKCAQEA90G53ufCi/ve5hO3+Ic4/mDSBq37rGzBABQb5955M/R2aslI
........ sample code private key parse here. .. . .. .
4aN1SyfDresMaTTRrKxmvxDbsvGOHahh+LgfAqKYMGyINcWWjGhzkcIu8eS2YZ/A
m6x973lPiMEEJzjhYavi9VQQbo+spHfZ/m1NPqLOy9xytaah+zzab+Y=
-----END PRIVATE KEY-----`
var publicBlockType string = "PUBLIC KEY"
var privateBlockType string = "PRIVATE KEY"
var encryptLabel []byte = []byte("QWERTY")

/**
 * use the public key to encrypt the string
 * then return the base64 encded string
 *
 **/
func EncryptThis(text string, publicKeyPEMString []byte) (string, error) {

	// get the public key
	block, _ := pem.Decode(publicKeyPEMString)

	if block == nil || block.Type != publicBlockType {
		return "", errors.New("Failed to decode pem block")
	}
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, publicKey, []byte(text), encryptLabel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return "", err
	}
	base64ed := base64.StdEncoding.EncodeToString(ciphertext)
	return base64ed, nil

}
func DecryptThis(enText string, privateKeyBytes []byte) ([]byte, error) {
	privateKeyBytes = []byte(privateKey)
	//
	block, _ := pem.Decode(privateKeyBytes)

	if block == nil || block.Type != privateBlockType {
		return nil, errors.New("pem decode error")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rng := rand.Reader
	//base64 decode
	encryptedBytes, _ := base64.StdEncoding.DecodeString(enText)
	decodeText, err := rsa.DecryptOAEP(sha256.New(), rng, privateKey, encryptedBytes, encryptLabel)
	if err != nil {
		return nil, err
	}
	return decodeText, nil
}

//GetFileContents get file contents
func GetFileContents(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	fileContents, err := ioutil.ReadAll(f)
	f.Close()
	return fileContents, err
}

func GenRSAPair(publiKeyFile, privateKeyFile string) error {
	// generate key
	privatekey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		return err
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  privateBlockType,
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create(privateKeyFile)
	defer privatePem.Close()
	if err != nil {
		fmt.Printf("error when create private.pem: %s \n", err)
		return err
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		fmt.Printf("error when encode private pem: %s \n", err)
		return err
	}

	// dump public key to file
	//publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publickey)
	publicKeyBlock := &pem.Block{
		Type:  publicBlockType,
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create(publiKeyFile)
	defer publicPem.Close()
	if err != nil {
		fmt.Printf("error when create public.pem: %s \n", err)
		return err
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		fmt.Printf("error when encode public pem: %s \n", err)
		return err
	}
	return nil
}
