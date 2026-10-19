package submodules

import (
	"io"
	"net/http"
	"time"
)

const (
	probeTimeout = 8 * time.Second
	probeBytes   = 1 << 20
)

func httpGet(client *http.Client, target string) (int, []byte, string, error) {
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, "", err
	}
	request.Header.Set("User-Agent", "clouseau/1.0")

	response, err := client.Do(request)
	if err != nil {
		return 0, nil, "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, probeBytes))
	if err != nil {
		return response.StatusCode, nil, response.Header.Get("Location"), err
	}
	return response.StatusCode, body, response.Header.Get("Location"), nil
}
