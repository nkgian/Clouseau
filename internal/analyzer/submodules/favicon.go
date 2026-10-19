package submodules

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

type FaviconInfo struct {
	URL    string `json:"url"`
	Bytes  int    `json:"bytes,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	MMH3   int32  `json:"mmh3,omitempty"`
	Error  string `json:"error,omitempty"`
}

func FetchFavicon(baseURL string) *FaviconInfo {
	target := strings.TrimSuffix(baseURL, "/") + "/favicon.ico"
	info := &FaviconInfo{URL: target}

	client := &http.Client{Timeout: probeTimeout}
	status, body, _, err := httpGet(client, target)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	if status != http.StatusOK {
		info.Error = fmt.Sprintf("status %d", status)
		return info
	}
	if len(body) == 0 {
		info.Error = "empty favicon"
		return info
	}

	info.Bytes = len(body)
	info.SHA256 = fmt.Sprintf("%x", sha256.Sum256(body))
	info.MMH3 = ShodanFaviconHash(body)
	return info
}

func ShodanFaviconHash(data []byte) int32 {
	return int32(Murmur3Sum32([]byte(pythonBase64(data)), 0))
}

func Murmur3Sum32(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)

	length := len(data)
	hash := seed
	roundedEnd := length & 0xfffffffc

	for i := 0; i < roundedEnd; i += 4 {
		block := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
		block *= c1
		block = (block << 15) | (block >> 17)
		block *= c2

		hash ^= block
		hash = (hash << 13) | (hash >> 19)
		hash = hash*5 + 0xe6546b64
	}

	var tail uint32
	switch length & 3 {
	case 3:
		tail ^= uint32(data[roundedEnd+2]) << 16
		fallthrough
	case 2:
		tail ^= uint32(data[roundedEnd+1]) << 8
		fallthrough
	case 1:
		tail ^= uint32(data[roundedEnd])
		tail *= c1
		tail = (tail << 15) | (tail >> 17)
		tail *= c2
		hash ^= tail
	}

	hash ^= uint32(length)
	hash ^= hash >> 16
	hash *= 0x85ebca6b
	hash ^= hash >> 13
	hash *= 0xc2b2ae35
	hash ^= hash >> 16

	return hash
}

func pythonBase64(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	if encoded == "" {
		return ""
	}

	var b strings.Builder
	for len(encoded) > 76 {
		b.WriteString(encoded[:76])
		b.WriteString("\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded)
	b.WriteString("\n")
	return b.String()
}
