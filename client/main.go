package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/DataDog/gohai/cpu"
	"github.com/DataDog/gohai/filesystem"
	"github.com/DataDog/gohai/memory"
	"github.com/DataDog/gohai/network"
	"github.com/DataDog/gohai/platform"
//	"github.com/mitchellh/go-ps"
	"github.com/pborman/getopt/v2"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	localUserOpt   = getopt.StringLong("local-user", 'u', "", "use USER-ID to sign", "USER-ID")
	detachSignFlag = getopt.BoolLong("detach-sign", 'b', "make a detached signature")
	armorFlag      = getopt.BoolLong("armor", 'a', "create ascii armored output")
	statusFdOpt    = getopt.IntLong("status-fd", 0, -1, "write special status strings to the file descriptor n.", "n")
	signFlag       = getopt.BoolLong("sign", 's', "make a signature")
	fileArgs       []string
	stdout         io.WriteCloser = os.Stdout
)

func main() {
	// Parse CLI args
	getopt.HelpColumn = 40
	getopt.SetParameters("[files]")
	getopt.Parse()
	fileArgs = getopt.Args()

	f, err := os.OpenFile("/tmp/gitsec.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	logger := log.New(f, "prefix", log.LstdFlags)
	logger.Println(fileArgs)

	if *signFlag {
		// login prompt
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, os.ModePerm)
		if err != nil {
			log.Fatalln(err)
		}
		defer tty.Close()
		os.Stdout = tty
		HandleOpenIDFlow("example-app", "", "http://localhost:8080/callback", "http://127.0.0.1:5556/dex/auth", "http://127.0.0.1:5556/dex/token")
		var f io.ReadCloser
		if len(fileArgs) == 1 {
			if f, err = os.Open(fileArgs[0]); err != nil {
				logger.Println(errors.Wrapf(err, "failed to open message file (%s)", fileArgs[0]))
			}
			defer f.Close()
		} else {
			f = os.Stdin
		}

		dataBuf := new(bytes.Buffer)
		if _, err = io.Copy(dataBuf, f); err != nil {
			logger.Println(errors.Wrap(err, "failed to read message from stdin"))
		}

		fmt.Println(GetSystemInfo())

		logger.Println(dataBuf.String())
		fmt.Println(dataBuf.String())
		//log.Println(signMessage())
	}

}

func signMessage() (response string) {
	//Encode the data
	postBody, _ := json.Marshal(map[string]string{
		"name":  "Toby",
		"email": "Toby@example.com",
	})
	responseBody := bytes.NewBuffer(postBody)
	//Leverage Go's HTTP Post function to make request
	resp, err := http.Post("https://localhost/sign", "application/json", responseBody)
	//Handle Error
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	}
	defer resp.Body.Close()

	//Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	return sb
}

type Collector interface {
	Name() string
	Collect() (interface{}, error)
}

var collectors = []Collector{
	&cpu.Cpu{},
	&filesystem.FileSystem{},
	&memory.Memory{},
	&network.Network{},
	&platform.Platform{},
}

func Collect() (result map[string]interface{}, err error) {
	result = make(map[string]interface{})

	for _, collector := range collectors {
		c, _ := collector.Collect()
		if c != nil {
			result[collector.Name()] = c
		}
	}

	return
}

func GetSystemInfo() map[string]interface{} {
	// Collect local node data
	gohai, err := Collect()

	if err != nil {
		panic(err)
	}

	return gohai
}

type callbackEndpoint struct {
	server         *http.Server
	code           string
	shutdownSignal chan string
}

func (h *callbackEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	code := r.URL.Query().Get("code")
	if code != "" {
		h.code = code
		fmt.Fprintln(w, "Login is successful, You may close the browser and goto commandline")
	} else {
		fmt.Fprintln(w, "Login is not successful, You may close the browser and try again")
	}
	h.shutdownSignal <- "shutdown"
}

func HandleOpenIDFlow(clientID, clientSecret, callbackURL, authzEp, tokenEp string) {
	callbackEndpoint := &callbackEndpoint{}
	callbackEndpoint.shutdownSignal = make(chan string)
	server := &http.Server{
		Addr:           ":8080",
		Handler:        nil,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	callbackEndpoint.server = server
	http.Handle("/callback", callbackEndpoint)
	authzURL, authzURLParseError := url.Parse(authzEp)

	if authzURLParseError != nil {
		log.Fatal(authzURLParseError)
	}
	query := authzURL.Query()
	query.Set("response_type", "code")
	query.Set("scope", "openid")
	query.Set("client_id", clientID)
	query.Set("redirect_uri", callbackURL)
	authzURL.RawQuery = query.Encode()

	cmd := exec.Command("open", authzURL.String())
	cmdErorr := cmd.Start()
	if cmdErorr != nil {
		log.Fatal(authzURLParseError)
	}

	go func() {
		server.ListenAndServe()
	}()

	<-callbackEndpoint.shutdownSignal
	callbackEndpoint.server.Shutdown(context.Background())
	fmt.Println("Authorization code is ", callbackEndpoint.code)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	vals := url.Values{}
	vals.Set("grant_type", "authorization_code")
	vals.Set("code", callbackEndpoint.code)
	vals.Set("redirect_uri", callbackURL)
	req, requestError := http.NewRequest("POST", tokenEp, strings.NewReader(vals.Encode()))
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, clientError := client.Do(req)
	if clientError != nil {
		log.Fatal(clientError)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	log.Println(result)
	if result != nil {
		jsonStr, marshalError := json.Marshal(result)
		if marshalError != nil {
			log.Fatal(marshalError)
		}
		fmt.Println(string(jsonStr))
	} else {
		fmt.Println("Error while getting ID token")
	}
}
