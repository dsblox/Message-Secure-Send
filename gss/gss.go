package main

import (
	"io"
	"log"
	"flag"
	"strings"
	"net/http"
	"net/url"
	"encoding/json"
	crypto "github.com/dsblox/mss/encrypt"
)

/*
=============================================================================
 Secure Message Stuff
-----------------------------------------------------------------------------
 This section holds my Secure Message Server - an API for encrypting / 
 decrypting messages.  The server works with GET or POST and returns JSON
 (it also returns a "raw" response if requested which makes some testing 
 easier).

 Access the API at host:port/mss/ (the trailing slash appears needed for now)

   - on any call:
       . inputs: Cmd=<see below>, ResponseFormat=<json or raw>
       . JSON returns: Error=<OK or error message>

   - to encrypt: 
       . inputs: Cmd=encrypt, Passphrase=XXX, Plaintext=YYYY
       . JSON returns: CipherText=ZZZZ
       . raw returns: Plaintext or error message

   - to decrypt: 
       . inputs: Cmd=decrypt, Passphrase=XXX, Ciphertext=ZZZZ
       . JSON returns: Plaintext=YYYY
       . raw returns: Plaintext or error message

   - server status:
       . inputs: Cmd=status
       . JSON returns: Status=<current status>
       . raw returns: <current status>
===========================================================================*/

// utility function that loads a provided interface up
// with fields in a JSON request.  If a pure empty interface{}
// is provided this fills it with all fields.  If a type that
// defines its own fields is provided, it fills all matching
// externally-accessible (capitalized) fields.  Used below to
// fill a Message type from HTTP POSTs.
func DecodeJson(r *http.Request, o interface{}) (error) {
	raw := make([]byte, r.ContentLength)
	_, err := io.ReadFull(r.Body, raw)
	if err == nil {
		err = json.Unmarshal(raw, &o)
	}
	return err;
}




/*
=============================================================================
 Message struct
-----------------------------------------------------------------------------
 This structure is used for internal communication and to easily convert
 incoming parameters.  It is designed to hold both input and output parameters
 and simply ignores the fields it doesn't use for it's particular use at the
 time.  For example, when encrypting it doesn't use the Ciphertext field
 for inputs, but it does for outputs.

 ResponseFormat string - can currently be raw or json
 Cmd            string - can be status, encrypt or decrypt
 Passphrase     string - passphrase used to encrypt or decrypt
 Plaintext      string - string to encrypt, or result of decryption
 Ciphertext     string - result of encryption, or string to decrypt
 Status         string - used to return server status only
 Error          string - used for all results: OK or error-message
 
 Methods:
 	Json - convert to JSON
 	String - convert to string (JSON representation)
 	url.Values - convert to url.Values map - allows clean use of GET and POST
 	DecodeFromHTTP - fill Message object from HTTP request
===========================================================================*/
type Message struct {
	ResponseFormat string
	Cmd string
	Passphrase string
	Plaintext string
	Ciphertext string
	Status string
	Error string
}

func (msg Message) Json() []byte {
	j, _ := json.Marshal(msg)
	return j
}
func (msg Message) String() string {
	j := msg.Json()
	return string(j)
}

func (msg Message) UrlValues() url.Values {
	values := url.Values{}
	values.Set("Cmd", msg.Cmd)
	values.Set("Passphrase", msg.Passphrase)
	values.Set("Plaintext", msg.Plaintext)
	values.Set("Ciphertext", msg.Ciphertext)
	values.Set("ResponseFormat", msg.ResponseFormat)
	values.Set("Error", msg.Error)
	return values
}

func (msg *Message) DecodeFromHTTP(r *http.Request) (error) {
	return DecodeJson(r, msg);
}




// this is our API object - we can store some state here someday if we want
type MessageSecureSend struct { }


/*
=============================================================================
 generatePayload(message Message, e error) - convert a message to JSON response
   -- not sure this really needs its own function
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
		payload = message.Json()
	}
	return payload
}

/*
=============================================================================
 ProcessCommand()
-----------------------------------------------------------------------------
 This is the main command processor that decides what commands have been
 requested of this server, and routes or executes the commands.  This function
 takes a command and a set of parameters (in url.Values format) and returns
 a Message struct filled with the appropriate results.

 Note that returns are always through the Message type which always includes
 and Error field which will be "OK" on success, and have an error message on
 failure.

 Inputs: cmd    string      - encrypt, decrypt or status
         params url.Values  - expected values depend on the cmd, see below
         r      request     - currently needed only to log appropriately

 encrypt:
         inputs: Passphrase - passphrase to use to encrypt plaintext
                 Plaintext  - text to encrypt   
         return: Ciphertext - encrypted result

 decrypt:
         inputs: Passphrase - passphrase to use to decrypt ciphertext
                 Ciphertext - text to decrypt   
         return: Plaintext  - decrypted result

 status return:  Status     - status string for server (used for testing)
===========================================================================*/
func (mss MessageSecureSend) ProcessCommand(cmd string, params url.Values, r *http.Request) Message {
	var result Message
	switch cmd {

	case "encrypt":
		passphrase := params["Passphrase"][0]
		plaintext := params["Plaintext"][0]
		ciphertext, err := crypto.Encrypt(passphrase, plaintext)
		if err == nil {
			result.Ciphertext = ciphertext
			result.Error = "OK"
		} else {
			result.Error = err.Error()
		}

	case "decrypt":
		passphrase := params["Passphrase"][0]
		ciphertext := params["Ciphertext"][0]
		plaintext, err := crypto.Decrypt(passphrase, ciphertext)
		if err == nil {
			result.Plaintext = plaintext
			result.Error = "OK"
		} else {
			result.Error = err.Error()
		}
	
	case "status":
		result.Status = "Message Secure Send Server Running"
		result.Error = "OK"

	default:
		result.Error = "Unrecognized command: " + cmd
	}

	// log what we're doing
	if result.Error == "OK" {
		log.Printf("%s Cmd:%s successful\n", r.RemoteAddr, cmd)
	} else {
		log.Printf("%s Cmd:%s error: %s\n", r.RemoteAddr, cmd, result.Error)
	}

	return result
}

/*
=============================================================================
 selectRawResponse()
-----------------------------------------------------------------------------
 Process command doesn't want to care about the 1% case when our clients
 want to test us and get a raw string as a response, so we re-switch on the
 cmd and extract from the result a single string that makes the most sense
 if a tester wants a simple raw result from the server.
===========================================================================*/
func selectRawResponse(cmd string, result Message) string {
	var raw string
	if result.Error != "OK" {
		raw = result.Error
	} else {
		switch cmd {
		case "status":
			raw = result.Status
		case "encrypt":
			raw = result.Ciphertext
		case "decrypt":
			raw = result.Plaintext
		default:
			raw = "internal error"
		}
	}
	return raw
}

/*
=============================================================================
 ServeHTTP()
-----------------------------------------------------------------------------
 This interface handles HTTP requests and is called from the http.Handler.
 It simply takes as input a request and offers a ReponseWriter into which
 to write the reposne.

 Our server attempts to support all the same parameters regardless of HTTP
 method used: GET or POST.  This function switches on the HTTP method and
 extracts the appropriate inputs from the request before calling the command
 processor to do the work.

 Our server also attempts to support multiple output formats (currently JSON
 and this thing I call "raw" - which is just a text string holding the cmd
 results or an error message).  This method also decides how to write the
 correct reponse format.

 Note that we take advantage of built-in tools to parse incoming and
 outgoing JSON, which requires that our parameters be capitalized (since
 some of the marshalling only works with exposed struct fields).
===========================================================================*/
func (mss MessageSecureSend) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// we'll collect these inputs differently for GET and POST
	var cmd string
	var responseFormat string
	var params url.Values
	validMethod := true

	// collect the inputs for further processing
	switch r.Method {
	case "GET":
		err := r.ParseForm()
		if err == nil {
			cmd = r.FormValue("Cmd")
			responseFormat = r.FormValue("ResponseFormat")
			params = r.Form
		}

	case "POST":
		var msg Message
		err := msg.DecodeFromHTTP(r)
		// err := DecodeJson(r, &msg)
		if err == nil {
			cmd = msg.Cmd
			responseFormat = msg.ResponseFormat
			params = msg.UrlValues()
		}

	default:
		io.WriteString(w, "Unsupported HTTP Method")
		validMethod = false // set this to false so we don't continue processing
	}

	// if we got the basics we need go ahead and process our command
	if validMethod {
		result := mss.ProcessCommand(cmd, params, r)
		if responseFormat == "raw" {
			io.WriteString(w, selectRawResponse(cmd, result))
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Write(generatePayload(result, nil))
		}
	}

}



/*
=============================================================================
 main() - set up HTTP server and await commands
   -html - specifies the path on the server from which html files are served (default = client)
   -certs - specifies the path on the server from when certificates are served (default = .)
   -port = specifies the port the server will listen on (default = 4000)

 Using the Server:

  GSS is the server portion of the program and is accessible only via the
  API.  Access the API via host:port/mss/?cmd=CMD, with CMDs...
    . status - returns server status
    . encrypt - encrypt a plaintext=MESSAGE using passphrase=PASSWORD
    . decrypt - decrypt a ciphertext=ENCRYPTED using passphrase=PASSWORD
    . see comment above ProcessCommand() for more details
---------------------------------------------------------------------------*/
func main() {
	log.Printf("Mail Secure Send Server Started - Welcome\n")

	// flags indicate the location of system resources:
	// -html - absolute path to client files (will be accessible at /)
	// -certs - absolute path to TLS cert files
	// -port - port number on which to listen for requests
	var static_files_location string
	var certs_location string
	var listenport string
	flag.StringVar(&static_files_location, "html", "./client", "specify path to static web files on this server")
	flag.StringVar(&certs_location, "certs", ".", "specify path to static web files on this server")
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
	
	// lets try to get into HTTP ourselves at /mss
	http.Handle("/mss/", &MessageSecureSend{})	
	
	// use built-in file server to serve our client application at /
	log.Printf("...serving static pages from %s\n", static_files_location)
	http.Handle("/", http.FileServer(http.Dir(static_files_location)))

	// log 
	log.Printf("...serving certificates from %s\n", certs_location)
	log.Printf("...listening on port%s\n", listenport)
	err := http.ListenAndServeTLS(listenport, certs_location + "self-signed.crt", certs_location + "server.key", nil)
	if err != nil {
		log.Fatal(err)
	}
}



