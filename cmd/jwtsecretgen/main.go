package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func main() {
	bytes := make([]byte, 128)
	_, _ = rand.Read(bytes)

	encodedBytes := base64.RawStdEncoding.EncodeToString(bytes)
	fmt.Println(encodedBytes)
}
