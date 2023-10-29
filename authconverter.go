package authconverter

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

type TokenSource string
type authType string

const (
	password  TokenSource = "password"
	username  TokenSource = "username"
	unchanged TokenSource = "full"
	combined  TokenSource = "combined"
)

const (
	HeaderName string = "Authorization"
)

const (
	basic  authType = "Basic"
	bearer authType = "Bearer"
)

// Config structure
type Config struct {
	tokenSource TokenSource `yaml:"tokenSource"`
	encodeToken bool        `yaml:"encodeToken"`
}

// Main struct
type AuthConverter struct {
	next        http.Handler
	tokenSource TokenSource
	encodeToken bool
}

// Gets token from passed header
func (e *AuthConverter) getToken(header string) (string, error) {
	splitHeader := strings.SplitN(header, " ", 2)
	if len(splitHeader) != 2 {
		return "", errors.New("invalid authorization header contents")
	}
	if splitHeader[0] != string(basic) {
		return "", errors.New("invalid authorization type")
	}
	basicTokenBase64 := splitHeader[1]

	if e.tokenSource == unchanged {
		return basicTokenBase64, nil
	}

	basicTokenDecoded, err := base64.StdEncoding.DecodeString(basicTokenBase64)
	if err != nil {
		return "", errors.New("Base64 decoding failed")
	}
	basicTokenParts := strings.SplitN(string(basicTokenDecoded), ":", 2)
	if len(basicTokenParts) != 2 {
		return "", errors.New("invalid value in authorization header")
	}

	switch e.tokenSource {
	case username:
		return basicTokenParts[0], nil
	case password:
		return basicTokenParts[1], nil
	case combined:
		return basicTokenParts[0] + basicTokenParts[1], nil
	default:
		return "", errors.New("invalid token source")
	}
}

// Entry point from Traefik
func (e *AuthConverter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	token, err := e.getToken(req.Header.Get(HeaderName))
	if err == nil {
		if e.encodeToken {
			token = base64.StdEncoding.EncodeToString([]byte(token))
		}
		authorization := "Bearer " + token
		rw.Header().Set(HeaderName, authorization)
	}

	e.next.ServeHTTP(rw, req)
}

func CreateConfig() *Config {
	return &Config{
		tokenSource: combined,
		encodeToken: false,
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	validConfig := map[TokenSource]bool{username: true, password: true, unchanged: true, combined: true}
	if !validConfig[config.tokenSource] {
		return nil, errors.New("invalid token source")
	}

	return &AuthConverter{
		next:        next,
		tokenSource: config.tokenSource,
		encodeToken: config.encodeToken,
	}, nil
}
