// Package jwt contains [JWT]-related helpers.
//
// The helpers only parse and decode tokens. They perform NO cryptographic
// verification: the signature, expiration and other claims are not checked,
// so they must not be used on their own to decide whether a token is
// authentic or authorized.
//
// [JWT]: https://en.wikipedia.org/wiki/JSON_Web_Token
package jwt
