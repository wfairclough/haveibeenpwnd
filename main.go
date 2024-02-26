package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func main() {
	fmt.Println("Check if your password has been pwned")
	fmt.Print("Enter Password: ")
  state, err := term.GetState(int(syscall.Stdin))
  if err != nil {
    fmt.Println("Error: ", err)
    os.Exit(1)
  }
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
  err = term.Restore(int(syscall.Stdin), state)
  if err != nil {
    fmt.Println("Error: ", err)
    os.Exit(1)
  }

	password := string(bytePassword)
  fmt.Println()

  checkPwned(password)
}

func checkPwned(plainTextPassword string) {
  hash := sha1.New()
  hash.Write([]byte(plainTextPassword))
  hashedPassword := hash.Sum(nil)
  hashedPasswordHex := strings.ToUpper(fmt.Sprintf("%x", hashedPassword))
  hashPrefix := hashedPasswordHex[:5]

  url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", hashPrefix)
  fmt.Println("Checking if your password has been pwned...")
  req, err := http.NewRequest("GET", url, nil)
  if err != nil {
    fmt.Println("Error: ", err)
    os.Exit(1)
  }

  req.Header.Set("User-Agent", "pwned-password-checker")
  
  client := &http.Client{}
  resp, err := client.Do(req)
  if err != nil {
    fmt.Println("Error: ", err)
    os.Exit(1)
  }

  if resp.StatusCode != 200 {
    fmt.Println("Error: ", resp.Status)
    os.Exit(1)
  }

  body, err := io.ReadAll(resp.Body)
  if err != nil {
    fmt.Println("Error: ", err)
    os.Exit(1)
  }

  // Search the results for the hashed password to see if it has been pwned
  lines := strings.Split(string(body), "\n")
  for _, line := range lines {
    parts := strings.Split(line, ":")
    if parts[0] == hashedPasswordHex[5:] {
      fmt.Print("Your password has not been pwned times: ")
      fmt.Println(parts[1])
      return
    }
  }
  fmt.Println("Your password did not appear in the database")

}

