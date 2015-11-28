package main

import (
	"fmt"
	"log"
	"flag"
	"strings"
	"net/http"
	"encoding/json"
	"code.google.com/p/gorest" 
	crypto "github.com/user/gss/encrypt"
)


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

	// service level configuration - sets the path over which the REST service will listen
	gorest.RestService `root:"/api/securemessage/" consumes:"application/json" produces:"application/json"`
	
	// end-point level configuration - only one for now: create a message from source (decode / encode)
	convertMessage gorest.EndPoint `method:"POST" path:"/messages/" postdata:"Message"`
	restTest gorest.EndPoint `method:"GET" path:"/resttest/{cmd:string}" output:"string"`
	showStatus gorest.EndPoint `method:"GET" path:"/status/" output:"string"`
	
	// client gorest.EndPoint `method:"GET" path:"/status/" output:"string"`
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
		plaintext, err := crypto.Decrypt(message.Passphrase, message.Body)
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
		ciphertext, err := crypto.Encrypt(message.Passphrase, message.Body)
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
   -html - specifies the path on the server from which html files are served (default = /files)
   -certs - specifies the path on the server from when certificates are served (default = /certs)
---------------------------------------------------------------------------*/

func main() {
	fmt.Printf("Welcome to Mail Secure Send Server\n")
	
	// flags indicate the location of system resources:
	// -html - absolute path to client files (will be available at /)
	// -certs - absolute path to TLS cert files
	var static_files_location string
	var certs_location string
	flag.StringVar(&static_files_location, "html", "/files", "specify path to static web files on this server")
	flag.StringVar(&certs_location, "certs", "/certs/", "specify path to static web files on this server")
	flag.Parse()
	if !strings.HasSuffix(certs_location, "/") {
		certs_location = certs_location + "/"
	}
	if strings.HasSuffix(static_files_location, "/") {
		static_files_location = strings.TrimSuffix(static_files_location, "/")
	}
	
	// use gorest to handle all HTTP requests to /api and file handler for /
	gorest.RegisterService(new(SecureMessageService))
	http.Handle("/api/", gorest.Handle())
	
	// use built-in file server to serve our client application (path?)
	fmt.Printf("...serving static pages from %s\n", static_files_location)
	http.Handle("/", http.FileServer(http.Dir(static_files_location)))
		
	fmt.Printf("...serving certificates from %s\n", certs_location)
	err := http.ListenAndServeTLS(":4000", certs_location + "self-signed.crt", certs_location + "server.key", nil)
	if err != nil {
		log.Fatal(err)
	}

}



