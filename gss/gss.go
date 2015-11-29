package main

import (
	"io"
	"fmt"
	"log"
	"flag"
	"strings"
	"errors"
	"net/http"
	"net/url"
	"encoding/json"
	"code.google.com/p/gorest" 
	crypto "github.com/dsblox/Message-Secure-Send/encrypt"
)

// TBD: Get rid of this GOREST crap and simply support my own HTTP-level stuff
// or look into XML-RPC.  Since there are no CRUD operations this server
// just does not want to be REST.


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
	Passphrase string
	Body string
	Status string
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
	getTest gorest.EndPoint `method:"GET" path:"/gettest/{cmd:string}" output:"string"`
	showStatus gorest.EndPoint `method:"GET" path:"/status/" output:"string"`
	
	// new main entry points - just an encrpyt and decrypt method
	encryptMessage gorest.EndPoint `method:"POST" path:"/encrypt/" postdata:"Message"`
	decryptMessage gorest.EndPoint `method:"POST" path:"/decrypt/" postdata:"Message"`
}

/*
=============================================================================
 decryptMessage(message Message) (Message, error)
-----------------------------------------------------------------------------
 Inputs:  crypto  Message - An encrypted message object
 Returns:         Message - New message object decrypted
                  error   - 
                  
 Decrypt the message returning a Message object with the body decrypted or
 return the error in the Status field.
===========================================================================*/
func decryptMessage(message Message) (Message, error) {
	var converted Message
	var err error

	// if incoming message is encoded then decrypt the body
	if message.Encoded {
		var plaintext string
		plaintext, err = crypto.Decrypt(message.Passphrase, message.Body)
		if err == nil {
			converted.Body = string(plaintext)
			converted.Status = "Decrypted OK"
			fmt.Println("Message Decryption Successful")
		} else {
			fmt.Println("Message Decryption Failed") // TBD: figure out logging
		}
	} else {
		err = errors.New("Decryption requested but message not encoded.")
	}

	// if an error the return the error to client, but eat the error here
	if err != nil {
		converted.Status = err.Error()
		err = nil
	}
	
	return converted, err
}

/*
=============================================================================
 encryptMessage(message Message) (Message, error)
-----------------------------------------------------------------------------
 Inputs:  plainttext  Message - A message object with text and passphrase
 Returns:             Message - New message object cryptotext
                      error   - 
                  
 Encrypt the message returning a Message object with the body holding crypto
 or return the error in the Status field.
===========================================================================*/
func encryptMessage(message Message) (Message, error) {
	var converted Message
	var err error

	// if incoming message is not encoded then encrypt the body
	if !message.Encoded {
		var ciphertext string
		ciphertext, err = crypto.Encrypt(message.Passphrase, message.Body)
		if err == nil {
			converted.Body = ciphertext
			converted.Encoded = true
			converted.Status = "Encrypted OK"
			fmt.Println("Message Encryption Successful")
		} else {
			fmt.Println("Message Encryption Failed")
		}
	} else {
		err = errors.New("Encryption requested but message encoded.")
	}

	// if an error then return the error to client, but eat it here
	if (err != nil) {
		converted.Status = err.Error()
		err = nil
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
 generatePayload(message Message, e error) - convert a message to gorest response
---------------------------------------------------------------------------*/
func generatePayload(message Message, e error) []byte {
	var payload []byte
	if (false && e != nil) {
		// not sure why I'm not just eating the error and returning it
		// maybe i should eat any known errors and allow thrown messages
		// to be returned like this???
		// probably should have a generateErrorResponse()
		payload = []byte("Error: could not convert message")
	} else {
		payload,_ = gorest.InterfaceToBytes(message,"application/json")
	}
	return payload
}


/*
=============================================================================
 EncryptMessage(message Message) - encrypt
 DecryptMessage(message Message) - decrypt

 These are glue functions between the gorest endpoint definitions and the
 corresponding internal functions that actually make sense of the Message
 struct and call the crypto packages to do the actual translations.
---------------------------------------------------------------------------*/
func(serv SecureMessageService) EncryptMessage(message Message) {
	serv.generateOKResponse(generatePayload(encryptMessage(message)))
    return
}
func(serv SecureMessageService) DecryptMessage(message Message) {
	serv.generateOKResponse(generatePayload(decryptMessage(message)))
    return
}


/*
=============================================================================
 GetTest(cmd string) - test interface to GET for easy browser testing
---------------------------------------------------------------------------*/
func(serv SecureMessageService) GetTest(cmd string) string {
	var result string
	switch cmd {
		case "encrypt":
			result = "to be implemented"
		case "decrypt":
			result = "to be implemented"
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

// this is our API object - we can store some state here someday if we want
type MessageSecureSend struct { }

func (mss MessageSecureSend) ProcessCommand(cmd string, params url.Values) string {
	var result string
	switch cmd {
	case "encrypt":
		passphrase := params["passphrase"][0]
		plaintext := params["plaintext"][0]
		ciphertext, err := crypto.Encrypt(passphrase, plaintext)
		if err == nil {
			result = ciphertext
		} else {
			result = err.Error()
		}
	case "decrypt":
		passphrase := params["passphrase"][0]
		ciphertext := params["ciphertext"][0]
		plaintext, err := crypto.Decrypt(passphrase, ciphertext)
		if err == nil {
			result = plaintext
		} else {
			result = err.Error()
		}
	case "status":
		result = "Message Secure Send Server Running OK"
	default:
		result = "unknown test command"
	}
	return result
}

// implement one interface required by interface http.Handler
func (mss MessageSecureSend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		fallthrough
	case "POST":
		r.ParseForm()
		fmt.Println(r.Form)
		io.WriteString(w, mss.ProcessCommand(r.FormValue("cmd"), r.Form))
	default:
		io.WriteString(w, "Unsupported HTTP Method")
	}
}



/*
=============================================================================
 main() - set up gorest and HTTP server and await commands
   -html - specifies the path on the server from which html files are served (default = /files)
   -certs - specifies the path on the server from when certificates are served (default = /certs)
   -port = specifies the port the server will listen on (default = 4000)

 Using the Server:

  GSS is the server portion of the program and is accessible only via the
  API.  Access the API via host:port/api/securemessage/CMD, with CMDs...
    - GET:
       . status - returns server status
       . resttest - test interface to let me test various commands
    - POST:
       . messages - POST interface to convert a message in either direction
    - TBD-POST:
       . encrypt - encrypt a message and return cryptotext
       . decrypt - decrypt a message and return plaintext


---------------------------------------------------------------------------*/

func main() {
	fmt.Printf("Welcome to Mail Secure Send Server\n")

	// port on which we will listen (make part of configuration or command line?)

	
	// flags indicate the location of system resources:
	// -html - absolute path to client files (will be available at /)
	// -certs - absolute path to TLS cert files
	// -port - port number on which to listen for requests
	var static_files_location string
	var certs_location string
	var listenport string
	flag.StringVar(&static_files_location, "html", "/files", "specify path to static web files on this server")
	flag.StringVar(&certs_location, "certs", "/certs/", "specify path to static web files on this server")
	flag.StringVar(&listenport, "port", "4000", "specify port on which the server will take requests")
	flag.Parse()
	if !strings.HasSuffix(certs_location, "/") {
		certs_location = certs_location + "/"
	}
	if strings.HasSuffix(static_files_location, "/") {
		static_files_location = strings.TrimSuffix(static_files_location, "/")
	}
	if !strings.HasPrefix(listenport, ":") {
		listenport = ":" + listenport
	}
	
	// use gorest to handle all HTTP requests to /api and file handler for /
	gorest.RegisterService(new(SecureMessageService))
	http.Handle("/api/", gorest.Handle())

	// lets try to get into HTTP ourselves at /mss
	http.Handle("/mss/", &MessageSecureSend{})	
	
	// use built-in file server to serve our client application (path?)
	fmt.Printf("...serving static pages from %s\n", static_files_location)
	http.Handle("/", http.FileServer(http.Dir(static_files_location)))
		
	fmt.Printf("...serving certificates from %s\n", certs_location)
	fmt.Printf("...listening on port %s\n", listenport)
	err := http.ListenAndServeTLS(listenport, certs_location + "self-signed.crt", certs_location + "server.key", nil)
	if err != nil {
		log.Fatal(err)
	}

}



