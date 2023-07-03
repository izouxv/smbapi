package ntlmssp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"github/izouxv/smbapi/smb/encoder"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

/*
func convertUTF16ToLittleEndianBytes(u []uint16) []byte {
	b := make([]byte, 2*len(u))
	for index, value := range u {
		binary.LittleEndian.PutUint16(b[index*2:], value)
	}
	return b
}

// s.encode('utf-16le')
func UnicodeEncode(p string) []byte {
	return convertUTF16ToLittleEndianBytes(utf16.Encode([]rune(p)))
}

func MD4(data []byte) []byte {
	h := md4.New()
	h.Write(data)
	return h.Sum(nil)
}

func MD5(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

func HMAC_MD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// Version 2 of NTLM hash function
func Ntowfv2(password, user, domain string) []byte {
	return HMAC_MD5(MD4(UnicodeEncode(password)), UnicodeEncode(strings.ToUpper(user)+domain))
}

// Same as NTOWFv2
func Lmowfv2(password, user, domain string) []byte {
	return Ntowfv2(password, user, domain)
}
*/

func Ntowfv1(pass string) []byte {
	hash := md4.New()
	hash.Write(encoder.ToUnicode(pass))
	return hash.Sum(nil)
}

func Ntowfv2(pass, user, domain string) []byte {
	h := hmac.New(md5.New, Ntowfv1(pass))
	h.Write(encoder.ToUnicode(strings.ToUpper(user) + domain))
	return h.Sum(nil)
}

func Lmowfv2(pass, user, domain string) []byte {
	return Ntowfv2(pass, user, domain)
}

func NTPasswordHash(password string) string {
	input := utf16.Encode([]rune(password))
	h := md4.New()
	if err := binary.Write(h, binary.LittleEndian, input); err != nil {
		// these are all in-memory operations with no error modes,
		// but just in case
		panic(fmt.Errorf("impossible error hashing password: %w", err))
	}
	output := h.Sum(nil)
	// encode to conventional uppercase hex
	return fmt.Sprintf("%X", output)
}

func ComputeResponseNTLMv2(nthash, lmhash, clientChallenge, serverChallenge, timestamp, serverName []byte) []byte {

	temp := []byte{1, 1}
	temp = append(temp, 0, 0, 0, 0, 0, 0)
	temp = append(temp, timestamp...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, serverName...)
	temp = append(temp, 0, 0, 0, 0)

	return ComputeResponseNTLMv2Check(nthash, serverChallenge, temp)

	// h := hmac.New(md5.New, nthash)
	// h.Write(append(serverChallenge, temp...))
	// ntproof := h.Sum(nil)
	// return append(ntproof, temp...)
}

func ComputeResponseNTLMv2Check(nthash, serverChallenge, temp []byte) []byte {
	h := hmac.New(md5.New, nthash)
	h.Write(append(serverChallenge, temp...))
	ntproof := h.Sum(nil)
	return append(ntproof, temp...)
}

func NTLMv2KeyExchangeKey(ntProofStr []byte, password, name, domain string) []byte {
	// // https://msdn.microsoft.com/en-us/library/cc236700.aspx
	// byte[] responseKeyNT = NTLMCryptography.NTOWFv2(password, message.UserName, message.DomainName);
	// byte[] ntProofStr = ByteReader.ReadBytes(message.NtChallengeResponse, 0, 16);
	// sessionBaseKey = new HMACMD5(responseKeyNT).ComputeHash(ntProofStr);
	// keyExchangeKey = sessionBaseKey;
	nthash := Ntowfv2(password, name, domain)
	h := hmac.New(md5.New, nthash)
	h.Write(ntProofStr)
	return h.Sum(nil)
}

func NTLMv2Verify(serverChallenge, clientChallengeStructurePadded []byte, password, name, domain string) []byte {
	nthash := Ntowfv2(password, name, domain)
	// logx.Printf("nthash: %v", nthash)
	temp := clientChallengeStructurePadded
	w := bytes.NewBuffer(make([]byte, 0))
	binary.Write(w, binary.LittleEndian, serverChallenge)

	h := hmac.New(md5.New, nthash)
	h.Write(append(serverChallenge, temp...))
	return h.Sum(nil)

	// return ComputeResponseNTLMv2Check(nthash, w.Bytes(), tail)
}
