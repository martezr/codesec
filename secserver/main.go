package main

import (
    "fmt"
    "log"
    "encoding/json"
    "net/http"
    "github.com/gorilla/mux"
   	"github.com/github/ietf-cms"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
     "crypto"
)

type CommitData struct {
  Commit string `json:"commit"`
}

func homePage(w http.ResponseWriter, r *http.Request){
    fmt.Fprintf(w, "Welcome to the HomePage!")
    fmt.Println("Endpoint Hit: homePage")
}

func signCommit(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "application/json")
  var commitoutput CommitData
  _ = json.NewDecoder(r.Body).Decode(&commitoutput)
  fmt.Println(r.Body)
  fmt.Println(commitoutput.Commit)
  sd, _ := cms.NewSignedData([]byte(commitoutput.Commit))
  fmt.Println(string(sd))
  json.NewEncoder(w).Encode(&commitoutput.Commit)
}


func handleRequests() {
    router := mux.NewRouter()
    router.HandleFunc("/sign", signCommit).Methods("POST")
    router.HandleFunc("/", homePage)
    log.Fatal(http.ListenAndServe(":8000", router))
}

func main() {
    handleRequests()
}

func signData(msg string) {

// The GenerateKey method takes in a reader that returns random bits, and
// the number of bits
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
	panic(err)
}


// Before signing, we need to hash our message
// The hash is what we actually sign
msgHash := sha256.New()
_, err = msgHash.Write([]byte(msg))
if err != nil {
	panic(err)
}
msgHashSum := msgHash.Sum(nil)

// In order to generate the signature, we provide a random number generator,
// our private key, the hashing algorithm that we used, and the hash sum
// of our message
signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
if err != nil {
	panic(err)
}
fmt.Println(string(signature))
}
