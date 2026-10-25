// One read-only account request. Never put a key in the source file.
package main

import (
	"context"
	"fmt"
	arnproxy "github.com/arnproxy/arnproxy-go"
	"os"
)

func main() {
	client, err := arnproxy.New(os.Getenv("ARNPROXY_API_KEY"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	response, err := client.Account(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var account struct {
		ID int `json:"id"`
	}
	if err := response.DecodeData(&account); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(account.ID)
}
