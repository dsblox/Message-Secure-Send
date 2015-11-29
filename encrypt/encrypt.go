package encrypt

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha1"
    "golang.org/x/crypto/pbkdf2"
    "encoding/base64"
    "errors"
    "strconv"
	"fmt"
	"io"
	"bytes"
)

/*
=============================================================================
 Encryption Stuff (break into its own file?)
-----------------------------------------------------------------------------
 This section holds my encryption wrappers to golang-supplied AES encryption
 where we have a standard salt for hashing passwords into keys, and have a
 standard digest prepended to any encrypted messages.
 
 External Entry Points:
 	Encrypt(passphrase string, plaintext string) string, error - encrypts
 	Decrypt(passphrase string, plaintext string) string, error - decrypts
 	
 Internal Helpers:
 	raw_encrypt(key, plaintext) - given AES key and full message with digest
 	raw_decrypt(key, ciphertext) - decrypts given AES key and full message with digest
 	genKey(passphrase string) - generate AES key from a passphrase
 	mySalt() - turn to constant? returns standard salt for key gen
 	myCheck() - turn to constant? returns standard prefix for digest
 	genDigest(plaintext) - generate entire digest to prepend to message
 	extractDigest(message) - parse and check digest when decrypting
===========================================================================*/

func mySalt() []byte {
	b := []byte{132, 21, 3, 244, 138, 6, 72, 88}
	return b
}
func myCheck() []byte {
	check := []byte("Q1bd5sW88ng00dAB")
	return check
}

/*
=============================================================================
 genDigest - generate digest to prepend to message for verification on decrypt
---------------------------------------------------------------------------*/
func genDigest(plaintext string) []byte {
	var digest bytes.Buffer
	digest.WriteString(string(myCheck()))
	digest.WriteString(fmt.Sprintf("|%d|", len(plaintext)))
	// consider - adding date/time of encryption to digest?
	return digest.Bytes()
}

/*
=============================================================================
 extractDigest - verify and remove digest from start of decrypted message
---------------------------------------------------------------------------*/
func extractDigest(message string) (string, error) {

	// make sure our check string is at the front and remove it
	check := myCheck()
	checkLen := 16 // len(check)
	bMessage := []byte(message)
	messageCheck := bMessage[:checkLen]
	if (bytes.Compare(messageCheck, check) != 0) {
		return "", errors.New("passphrase incorrect or message corrupt")
	}
	bMessage = bMessage[checkLen:]

	// extract the length, check it against the message and remove it
	if bMessage[0] != '|' {
		return "", errors.New("digest error: length not found")
	}
	bMessage = bMessage[1:]
	iSep := bytes.IndexByte(bMessage, '|')
	if iSep == -1 {
		return "", errors.New("digest error: length not found")
	}
	strDigestLen := bMessage[:iSep]
	bMessage = bMessage[iSep+1:]
	checksum, err := strconv.Atoi(string(strDigestLen))
	if (err != nil) {
		return "", errors.New("digest error: length found but not parsed")		
	}
	plaintext := string(bMessage)
	if checksum != len(plaintext) {
		return "", errors.New(fmt.Sprintf("digest error: checksum length %d does not match digest len %d",checksum,len(plaintext)))		
	}
	
	return plaintext, nil
}

/*
=============================================================================
 genKey - generate 256 bit salted AES key from a passphrase using SHA1 hash
---------------------------------------------------------------------------*/
func genKey(passphrase string) []byte {
	key := pbkdf2.Key([]byte(passphrase), mySalt(), 4096, 32, sha1.New)
	return key
}

/*
=============================================================================
 raw_encrypt - encrypt string to base64 crypto using AES
---------------------------------------------------------------------------*/
func raw_encrypt(key []byte, text string) (string, error) {
	plaintext := []byte(text)
 
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
 
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
 
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
 
	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}
 
/*
=============================================================================
 raw_decrypt - decrypt from base64 to decrypted string
---------------------------------------------------------------------------*/
func raw_decrypt(key []byte, cryptoText string) (string, error) {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)
 
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
 
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
 
	stream := cipher.NewCFBDecrypter(block, iv)
 
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
 
	return fmt.Sprintf("%s", ciphertext), nil
}

/*
=============================================================================
 encrypt - given plaintext, add digest and encrypt
---------------------------------------------------------------------------*/
func Encrypt(passphrase string, plaintext string) (string, error) {

	// prepend our digest so we can recognize decrypted string later
	var message bytes.Buffer
	message.WriteString(string(genDigest(plaintext)))
	message.WriteString(plaintext)
	
	// generate a secure key using SHA1
	key := genKey(passphrase)
	
	// run the encryption algortihm
	ciphertext, err := raw_encrypt(key, message.String())
	if (err != nil) {
		return "", err
	}
	
	// return the encrypted text
	return ciphertext, nil
}

/*
=============================================================================
 decrypt - given ciphertext w digest, decrypt, verify and remove digest
---------------------------------------------------------------------------*/
func Decrypt(passphrase string, ciphertext string) (string, error) {

	// generate a secure key using SHA1
	key := genKey(passphrase)
	
	// decrypt
	message, err := raw_decrypt(key, ciphertext)
	if (err != nil) {
		return "", err
	}
	
	// extract and test for correct digester
	plaintext, err := extractDigest(message)
	if (err != nil) {
		return "", err
	}
	
	// return resulting plaintext
	return plaintext, nil
}