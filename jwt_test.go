package jwt

import (
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"
)

func jwtFromFile(fn string) string {
	bb, err := os.ReadFile(fn)
	if err != nil {
		panic(err)
	}
	return string(bb)
}

// jwtWithPayload builds a structurally valid JWT carrying the given raw JSON payload.
func jwtWithPayload(payload string) string {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(`{"alg":"HS256","typ":"JWT"}`) + "." + enc(payload) + "." + enc("sig")
}

func TestParse(t *testing.T) {
	type args struct {
		jwt string
	}
	tests := []struct {
		name        string
		args        args
		wantHeader  string
		wantPayload string
		wantSig     string // expected signature, base64url-encoded
		wantErr     bool
	}{
		{name: "empty",
			args:    args{jwt: "  "},
			wantErr: true,
		},
		{name: "malformed",
			args:    args{jwt: jwtFromFile("testdata/token.no.dots")},
			wantErr: true,
		},
		{name: "malformed header",
			args:    args{jwt: jwtFromFile("testdata/token.header.not.base64")},
			wantErr: true,
		},
		{name: "empty header",
			args:    args{jwt: ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"},
			wantErr: true,
		},
		{name: "empty payload",
			args:    args{jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..sig"},
			wantErr: true,
		},
		{name: "malformed payload",
			args:       args{jwt: jwtFromFile("testdata/token.payload.not.base64")},
			wantHeader: `{"alg":"HS256","typ":"JWT"}`,
			wantErr:    true,
		},
		{name: "malformed signature",
			args:        args{jwt: jwtFromFile("testdata/token.signature.not.base64")},
			wantHeader:  `{"alg":"HS256","typ":"JWT"}`,
			wantPayload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
			wantErr:     true,
		},
		{name: "valid token",
			args:        args{jwt: jwtFromFile("testdata/token.token")},
			wantHeader:  `{"alg":"HS256","typ":"JWT"}`,
			wantPayload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
			wantSig:     "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		},
		{name: "surrounding whitespace ignored",
			args:        args{jwt: "  " + jwtFromFile("testdata/token.token") + "\n"},
			wantHeader:  `{"alg":"HS256","typ":"JWT"}`,
			wantPayload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
			wantSig:     "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHeader, gotPayload, gotSig, err := Parse(tt.args.jwt)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotHeader != tt.wantHeader {
				t.Errorf("Parse() gotHeader = %v, want %v", gotHeader, tt.wantHeader)
			}
			if gotPayload != tt.wantPayload {
				t.Errorf("Parse() gotPayload = %v, want %v", gotPayload, tt.wantPayload)
			}
			if gotSig := base64.RawURLEncoding.EncodeToString(gotSig); gotSig != tt.wantSig {
				t.Errorf("Parse() gotSig = %v, want %v", gotSig, tt.wantSig)
			}
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	validToken := jwtFromFile("testdata/token.token")
	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{name: "Parse empty", err: Valid("  "), wantErr: ErrMalformed},
		{name: "Parse wrong parts", err: Valid("a.b"), wantErr: ErrMalformed},
		{name: "Parse empty header", err: Valid(".eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"), wantErr: ErrMalformed},
		{name: "UnixTime claim not found", err: errFrom(UnixTime(validToken, "exp")), wantErr: ErrClaimNotFound},
		{name: "UnixTime not a number", err: errFrom(UnixTime(validToken, "name")), wantErr: ErrClaimType},
		{name: "UnixTime overflow", err: errFrom(UnixTime(jwtWithPayload(`{"iat":1e19}`), "iat")), wantErr: ErrClaimType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.wantErr) {
				t.Errorf("got error %v, want errors.Is(_, %v)", tt.err, tt.wantErr)
			}
		})
	}
}

// errFrom discards a non-error result, keeping only the error for errors.Is checks.
func errFrom[T any](_ T, err error) error { return err }

func TestTime(t *testing.T) {
	got, err := Time(jwtFromFile("testdata/token.token"), "iat")
	if err != nil {
		t.Fatalf("Time() error = %v", err)
	}
	if want := time.Unix(1516239022, 0); !got.Equal(want) {
		t.Errorf("Time() = %v, want %v", got, want)
	}
	if _, err := Time(jwtFromFile("testdata/token.token"), "exp"); !errors.Is(err, ErrClaimNotFound) {
		t.Errorf("Time() missing claim error = %v, want ErrClaimNotFound", err)
	}
}

func TestUnixTime(t *testing.T) {
	type args struct {
		jwt  string
		code string
	}
	tests := []struct {
		name    string
		args    args
		want    int64
		wantErr bool
	}{
		{name: "not a time",
			args: args{
				jwt:  jwtFromFile("testdata/token.token"),
				code: "name",
			},
			wantErr: true,
		},
		{name: "valid time",
			args: args{
				jwt:  jwtFromFile("testdata/token.token"),
				code: "iat",
			},
			want: 1516239022,
		},
		{name: "claim not found",
			args: args{
				jwt:  jwtFromFile("testdata/token.token"),
				code: "exp",
			},
			wantErr: true,
		},
		{name: "fractional rounds",
			args: args{
				jwt:  jwtWithPayload(`{"iat":1516239022.6}`),
				code: "iat",
			},
			want: 1516239023,
		},
		{name: "large int64 not truncated",
			args: args{
				jwt:  jwtWithPayload(`{"iat":9007199254740993}`),
				code: "iat",
			},
			want: 9007199254740993, // 2^53 + 1, would lose precision as float64
		},
		{name: "overflows int64",
			args: args{
				jwt:  jwtWithPayload(`{"iat":1e19}`),
				code: "iat",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnixTime(tt.args.jwt, tt.args.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnixTime() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("UnixTime() = %v, want %v", got, tt.want)
			}
		})
	}
}
