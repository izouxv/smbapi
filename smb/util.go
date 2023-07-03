package smb

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func CalculateSignature(SessionKey, data []byte, dialect uint16) ([]byte, error) {
	//3.1.4.1 Signing An Outgoing Message
	if dialect == DialectSmb_2_0_2 || dialect == DialectSmb_2_1 {
		return ValidMAC(SessionKey, data), nil
	}
	return nil, fmt.Errorf("NA")
}

func ValidMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return expectedMAC
	// return hmac.Equal(messageMAC, expectedMAC)
}
