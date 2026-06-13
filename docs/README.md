# jwt
[![Go Reference](https://pkg.go.dev/badge/github.com/solsw/jwt.svg)](https://pkg.go.dev/github.com/solsw/jwt)
[![GitHub](https://img.shields.io/badge/github--green?logo=github)](https://github.com/solsw/jwt)

Package **jwt** contains [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token)-related helpers for Go.

> [!IMPORTANT]
> These helpers only **parse and decode** tokens. They perform **no cryptographic
> verification**: the signature, expiration and other claims are **not** checked, so
> they must not be used on their own to decide whether a token is authentic or
> authorized. For full verification (signature, `exp`, `nbf`, issuer, …) use a
> dedicated JWT library.

## Install

```sh
go get github.com/solsw/jwt
```

## API

### `func Parse(jwt string) (header, payload string, signature []byte, err error)`

Splits a JWT into its three [structural parts](https://en.wikipedia.org/wiki/JSON_Web_Token#Structure)
and base64url-decodes each one. `header` and `payload` are returned as their decoded
JSON strings; `signature` is the raw decoded bytes.

- Surrounding whitespace (e.g. a trailing newline) is ignored.
- A token is rejected as malformed if it is empty, does not have exactly three
  dot-separated parts, has an empty header or payload, or has any part that is not
  valid base64url.
- On error, the components decoded **before** the failure are still returned (a
  payload error yields the already-decoded header, and so on); later components are
  zero.

### `func Valid(jwt string) error`

Reports whether `jwt` is well-formed (i.e. parses via `Parse`). Returns `nil` if
well-formed. **No** cryptographic verification is performed — see the note above.

### `func UnixTime(jwt, code string) (int64, error)`

Returns the [Unix time](https://en.wikipedia.org/wiki/Unix_time) (seconds) from the
claim named `code` in the payload — useful for standard time claims such as `iat`,
`exp` and `nbf`.

- Integer claims that fit in `int64` are returned exactly (no float64 precision loss).
- Fractional values are rounded to the nearest integer.
- Values outside the `int64` range yield an error.

### `func Time(jwt, code string) (time.Time, error)`

Convenience wrapper around `UnixTime` that returns the claim as a `time.Time`
(`time.Unix(n, 0)`).

## Errors

The package wraps these sentinel errors; test for them with
[`errors.Is`](https://pkg.go.dev/errors#Is):

| Error              | Meaning                                                            |
| ------------------ | ----------------------------------------------------------------- |
| `ErrMalformed`     | The JWT is not well-formed (empty, wrong part count, undecodable). |
| `ErrClaimNotFound` | The requested claim is absent from the payload.                   |
| `ErrClaimType`     | The claim exists but is not an `int64`-valued number.             |

## Examples

```go
package main

import (
	"errors"
	"fmt"

	"github.com/solsw/jwt"
)

func main() {
	const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	header, payload, _, err := jwt.Parse(token)
	if err != nil {
		panic(err)
	}
	fmt.Println(header)  // {"alg":"HS256","typ":"JWT"}
	fmt.Println(payload) // {"sub":"1234567890","name":"John Doe","iat":1516239022}

	iat, err := jwt.Time(token, "iat")
	if err != nil {
		panic(err)
	}
	fmt.Println(iat.UTC()) // 2018-01-18 01:30:22 +0000 UTC

	// Optional claims: distinguish "absent" from other errors.
	if _, err := jwt.UnixTime(token, "exp"); errors.Is(err, jwt.ErrClaimNotFound) {
		fmt.Println("no expiration claim")
	}
}
```
