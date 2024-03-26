package jwt

import (
	"os"
	"testing"
)

func jwtFromFile(fn string) string {
	bb, err := os.ReadFile(fn)
	if err != nil {
		panic(err)
	}
	return string(bb)
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
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHeader, gotPayload, _, err := Parse(tt.args.jwt)
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
		})
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
