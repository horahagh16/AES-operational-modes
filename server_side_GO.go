package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// Generate a new AES key
func generateKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

// Pad plaintext to a multiple of block size
func pad(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

// Encrypt plaintext using the specified AES mode
func encrypt(plaintext, passphrase, mode string) (string, error) {
	key := generateKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	switch mode {
	case "ECB":
		return encryptECB(plaintext, block)
	case "CBC":
		return encryptCBC(plaintext, block)
	case "CFB":
		return encryptCFB(plaintext, block)
	case "CTR":
		return encryptCTR(plaintext, block)
	case "GCM":
		return encryptGCM(plaintext, block)
	default:
		return "", fmt.Errorf("unsupported mode: %s", mode)
	}
}

// Encrypt plaintext using AES-ECB
func encryptECB(plaintext string, block cipher.Block) (string, error) {
	plaintextBytes := pad([]byte(plaintext), block.BlockSize())
	ciphertext := make([]byte, len(plaintextBytes))
	for bs, be := 0, block.BlockSize(); bs < len(plaintextBytes); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Encrypt(ciphertext[bs:be], plaintextBytes[bs:be])
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Encrypt plaintext using AES-CBC
func encryptCBC(plaintext string, block cipher.Block) (string, error) {
	plaintextBytes := pad([]byte(plaintext), block.BlockSize())
	ciphertext := make([]byte, aes.BlockSize+len(plaintextBytes))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCBCEncrypter(block, iv)
	stream.CryptBlocks(ciphertext[aes.BlockSize:], plaintextBytes)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Encrypt plaintext using AES-CFB
func encryptCFB(plaintext string, block cipher.Block) (string, error) {
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Encrypt plaintext using AES-CTR
func encryptCTR(plaintext string, block cipher.Block) (string, error) {
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Encrypt plaintext using AES-GCM
func encryptGCM(plaintext string, block cipher.Block) (string, error) {
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func main() {
	passphrase := "my_secret_passphrase"
	plaintext := "Hello, World!"
	mode := "GCM" // Change this to "ECB", "CBC", "CFB", "CTR", or "GCM" as needed

	encrypted, err := encrypt(plaintext, passphrase, mode)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}
	fmt.Println("Encrypted:", encrypted)
}
