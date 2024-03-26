package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
)

// Parse [parses] a [JWT].
//
// [parses]: https://en.wikipedia.org/wiki/JSON_Web_Token#Structure
// [JWT]: https://en.wikipedia.org/wiki/JSON_Web_Token
func Parse(jwt string) (header, payload string, signature []byte, err error) {
	if len(strings.TrimSpace(jwt)) == 0 {
		return "", "", nil, errors.New("empty JWT")
	}
	pp := strings.Split(jwt, ".")
	if len(pp) != 3 {
		return "", "", nil, errors.New("malformed JWT")
	}
	bbHeader, err := base64.RawURLEncoding.DecodeString(pp[0])
	if err != nil {
		return "", "", nil, fmt.Errorf("malformed JWT header: %w", err)
	}
	bbPayload, err := base64.RawURLEncoding.DecodeString(pp[1])
	if err != nil {
		return string(bbHeader), "", nil, fmt.Errorf("malformed JWT payload: %w", err)
	}
	bbSignature, err := base64.RawURLEncoding.DecodeString(pp[2])
	if err != nil {
		return string(bbHeader), string(bbPayload), nil, fmt.Errorf("malformed JWT signature: %w", err)
	}
	return string(bbHeader), string(bbPayload), bbSignature, nil
}

// Valid determines whether 'jwt' is valid.
func Valid(jwt string) error {
	_, _, _, err := Parse(jwt)
	return err
}

// UnixTime returns Unix time from claim with 'code' (if any) from [JWT]'s [payload]
// (e.g., may be used to get 'Issued at' from JWT's payload [Standard fields]).
//
// [JWT]: https://en.wikipedia.org/wiki/JSON_Web_Token
// [payload]: https://en.wikipedia.org/wiki/JSON_Web_Token#Structure
// [Standard fields]: https://en.wikipedia.org/wiki/JSON_Web_Token#Standard_fields
func UnixTime(jwt, code string) (int64, error) {
	_, payload, _, err := Parse(jwt)
	if err != nil {
		return 0, err
	}
	var pl map[string]any
	if err := json.Unmarshal([]byte(payload), &pl); err != nil {
		return 0, err
	}
	for k, v := range pl {
		if k == code {
			ut, ok := v.(float64)
			if !ok {
				return 0, fmt.Errorf("claim with code '%s' does not contain number", code)
			}
			r := math.Round(ut)
			if !(math.MinInt64 <= r && r <= math.MaxInt64) {
				return 0, fmt.Errorf("claim with code '%s' does not contain int64 value", code)
			}
			return int64(r), nil
		}
	}
	return 0, fmt.Errorf("claim with code '%s' not found in JWT's payload", code)
}
