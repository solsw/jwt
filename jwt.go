package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Sentinel errors returned (wrapped) by this package; test for them with [errors.Is].
var (
	// ErrMalformed indicates the JWT is not well-formed (empty, wrong number of
	// parts, empty/undecodable header, payload or signature).
	ErrMalformed = errors.New("malformed JWT")
	// ErrClaimNotFound indicates the requested claim is absent from the payload.
	ErrClaimNotFound = errors.New("claim not found")
	// ErrClaimType indicates the claim exists but is not an int64-valued number.
	ErrClaimType = errors.New("claim is not an int64-valued number")
)

// Parse [parses] a [JWT]. Surrounding whitespace (e.g. a trailing newline) is ignored.
//
// On error, the components decoded before the failure are still returned (so a payload
// error yields the already-decoded header, and so on); all later components are zero.
//
// [parses]: https://en.wikipedia.org/wiki/JSON_Web_Token#Structure
// [JWT]: https://en.wikipedia.org/wiki/JSON_Web_Token
func Parse(jwt string) (header, payload string, signature []byte, err error) {
	jwt = strings.TrimSpace(jwt)
	if len(jwt) == 0 {
		return "", "", nil, fmt.Errorf("%w: empty", ErrMalformed)
	}
	pp := strings.Split(jwt, ".")
	if len(pp) != 3 {
		return "", "", nil, fmt.Errorf("%w: want 3 dot-separated parts, got %d", ErrMalformed, len(pp))
	}
	if pp[0] == "" || pp[1] == "" {
		return "", "", nil, fmt.Errorf("%w: empty header or payload", ErrMalformed)
	}
	bbHeader, err := base64.RawURLEncoding.DecodeString(pp[0])
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	bbPayload, err := base64.RawURLEncoding.DecodeString(pp[1])
	if err != nil {
		return string(bbHeader), "", nil, fmt.Errorf("%w: payload: %w", ErrMalformed, err)
	}
	bbSignature, err := base64.RawURLEncoding.DecodeString(pp[2])
	if err != nil {
		return string(bbHeader), string(bbPayload), nil, fmt.Errorf("%w: signature: %w", ErrMalformed, err)
	}
	return string(bbHeader), string(bbPayload), bbSignature, nil
}

// Valid reports whether 'jwt' is well-formed (i.e. successfully parses via [Parse]).
//
// Valid performs NO cryptographic verification: it does not check the signature,
// expiration ('exp'), 'nbf', issuer or any other claim. It must not be used on its
// own to decide whether a token is authentic or authorized.
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
	// UseNumber so large integer claims are not silently truncated to float64.
	dec := json.NewDecoder(strings.NewReader(payload))
	dec.UseNumber()
	var pl map[string]any
	if err := dec.Decode(&pl); err != nil {
		return 0, fmt.Errorf("%w: payload is not a JSON object: %w", ErrMalformed, err)
	}
	v, ok := pl[code]
	if !ok {
		return 0, fmt.Errorf("%w: code %q", ErrClaimNotFound, code)
	}
	num, ok := v.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%w: code %q is not a number", ErrClaimType, code)
	}
	// Exact path: integer-valued claim that fits in int64.
	if i, err := num.Int64(); err == nil {
		return i, nil
	}
	// Fractional or out-of-int64-range: round, then bounds-check.
	f, err := num.Float64()
	if err != nil {
		return 0, fmt.Errorf("%w: code %q is not a number", ErrClaimType, code)
	}
	r := math.Round(f)
	// math.MaxInt64 is not representable as float64 (rounds up to 2^63), so compare
	// against the largest float64 that is <= math.MaxInt64 to avoid an overflowing conversion.
	const maxSafe = math.MaxInt64 - 1023
	if r < math.MinInt64 || r > maxSafe {
		return 0, fmt.Errorf("%w: code %q is out of int64 range", ErrClaimType, code)
	}
	return int64(r), nil
}

// Time returns the time from the claim with 'code' (if any) from [JWT]'s payload,
// interpreting the claim's value as Unix time in seconds (see [UnixTime]).
// It is a convenience wrapper that may be used for standard time claims like
// 'iat', 'exp' and 'nbf'.
//
// [JWT]: https://en.wikipedia.org/wiki/JSON_Web_Token
func Time(jwt, code string) (time.Time, error) {
	ut, err := UnixTime(jwt, code)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(ut, 0), nil
}
