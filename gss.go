package main

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
	"log"
	"bytes"
	"net/http"
	"encoding/json"
	"code.google.com/p/gorest" 
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
		return "", errors.New("passphrase incorrect")
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
func encrypt(passphrase string, plaintext string) (string, error) {

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
func decrypt(passphrase string, ciphertext string) (string, error) {

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

/*
=============================================================================
 Secure Message Stuff
-----------------------------------------------------------------------------
 This section holds my Secure Message Server - a REST API for encrypting / 
 decrypting messages.  The only "object" on the server for now is a
 Message - which can be in either encrypted or decrypted state.  Since this
 so-called REST server actually has no persistence, I'm representing every
 call as a POST to create a message (either encrypted or decrypted) from its
 opposite.
  
 Externally Visible:
 	POST /securemessage/messages/ - postdata: Message (application/json)
 	   - to encrypt: send plaintext in Body and Encoded false
 	   - to decrypt: send ciphertext in Body and Encoded true
 	   - NOTE: gorest mapped to ConvertMessage() function
 	GET /securemessage/resttest/cmd=XXX - test convenience function
 	Message Object - represents an encryptable or encrypted message
 	
 Internal Helpers:
 	convertMessage - decides if encrypt or decrypt is needed and does it
 	generateOKResponse - utility func to generate response with headers
===========================================================================*/


/*
=============================================================================
 Message struct
-----------------------------------------------------------------------------
 Encoded bool      - true if encrypted, false if plaintext
 Hint string       - right now using as error - TBD change name
 Passphrase string - passphrase to encrypt or decrypt - only set on input
 Body string       - ciphertext message (with digest) or plaintext
 
 Methods:
 	Json - convert to JSON
 	String - convert to string (JSON representation)
===========================================================================*/
type Message struct {
	Encoded bool
	Hint string
	Passphrase string
	Body string
}
func (msg Message) Json() []byte {
	j, _ := json.Marshal(msg)
	return j
}
func (msg Message) String() string {
	j := msg.Json()
	return string(j)
}

/*
=============================================================================
 Gorest Service Configuration - just 2 endpoints - see below for comments
---------------------------------------------------------------------------*/
type SecureMessageService struct {
	// service level configuration
	gorest.RestService `root:"/securemessage/" consumes:"application/json" produces:"application/json"`
	
	// end-point level configuration - only one for now: create a message from source (decode / encode)
	convertMessage gorest.EndPoint `method:"POST" path:"/messages/" postdata:"Message"`
	restTest gorest.EndPoint `method:"GET" path:"/resttest/{cmd:string}" output:"string"`
	showStatus gorest.EndPoint `method:"GET" path:"/status/" output:"string"`
}

/*
=============================================================================
 convertMessage(message Message) (Message, error)
-----------------------------------------------------------------------------
 Inputs:  message Message - Either an encrypted or decrypted message
 Returns:         Message - New message object in opposite state of input
                  error   - 
                  
 Encrypt or decrypt the message, depending on the state the input comes in.
 If msg.Encoded is true, then decrypt; if false then encrypt.  This function
 always returns a Message, even on errors, but will set only the "Hint"
 (TBD: change to Error field) with the error string.
===========================================================================*/
func convertMessage(message Message) (Message, error) {
	var converted Message
	var err error

	// if incoming message is encoded then decrypt the body
	if message.Encoded {
		plaintext, err := decrypt(message.Passphrase, message.Body)
		if err == nil {
			converted.Body = string(plaintext)
			converted.Encoded = false
			converted.Hint = "OK"
			fmt.Println("Message Decryption Successful")
		} else {
			converted.Hint = err.Error()
			fmt.Println("Message Decryption Failed") // TBD: figure out logging
		}

	
	// otherwise encrypt the body
	} else {
		ciphertext, err := encrypt(message.Passphrase, message.Body)
		if err == nil {
			converted.Body = ciphertext
			converted.Encoded = true
			converted.Hint = "OK"
			fmt.Println("Message Encryption Successful")
		} else {
			converted.Hint = err.Error()
			fmt.Println("Message Encryption Failed")
		}
	}
	return converted, err
}

/*
=============================================================================
 generateOKResponse(payload []byte) - utility to output success w any payload
---------------------------------------------------------------------------*/
func (serv SecureMessageService) generateOKResponse(payload []byte) {
	rb := serv.ResponseBuilder()
	rb.SetHeader("Content-Type","application/json")
	rb.SetResponseCode(200)
	rb.WriteAndOveride(payload)	
    return
}

/*
=============================================================================
 ConvertMessage(message Message) - encrypt or decrypt a message
---------------------------------------------------------------------------*/
func(serv SecureMessageService) ConvertMessage(message Message) {
	var payload []byte
	msgConverted, e := convertMessage(message)
	if (e != nil) {
		payload = []byte("Error: could not convert message")
	} else {
		payload,_ = gorest.InterfaceToBytes(msgConverted,"application/json")
	}
	serv.generateOKResponse(payload)
    return
}


/*
=============================================================================
 RestTest(cmd string) - test interface to GET for easy browser testing
---------------------------------------------------------------------------*/
func(serv SecureMessageService) RestTest(cmd string) string {
	var result string
	switch (cmd) {
		case "convert":
			// intent is to change this to read URL parameters and call convertMessage
			msgRaw := &Message{Encoded: false, Body: "this is a test"}
			msgConverted, _ := convertMessage(*msgRaw)
			result = msgConverted.String()
		case "status":
			result = "Message Secure Send Server Running OK"
		default:
			result = "unknown test command"
	}
    return result
}

/*
=============================================================================
 ShowStatus() - REST interface that shows the server is running
---------------------------------------------------------------------------*/
func(serv SecureMessageService) ShowStatus() string {
	return "Message Secure Send Server: Running OK"
}

/*
=============================================================================
 main() - set up gorest and HTTP server and await commands
---------------------------------------------------------------------------*/

func main() {
	fmt.Printf("Welcome to Mail Secure Send Server\n")
	
	// use gorest to handle all HTTP requests
	gorest.RegisterService(new(SecureMessageService))
	http.Handle("/", gorest.Handle())
		
	// err := http.ListenAndServe(":4000", nil)
	err := http.ListenAndServeTLS(":4000", "self-signed.crt", "server.key", nil)
	if err != nil {
		log.Fatal(err)
	}
}



