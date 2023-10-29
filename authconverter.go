package traefik_auth_converter

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

type TokenSource string
type AuthType string

const (
	password  TokenSource = "password"
	username  TokenSource = "username"
	unchanged TokenSource = "full"
	decoded   TokenSource = "decoded"
	combined  TokenSource = "combined"
)

const (
	HeaderName string = "Authorization"
)

const (
	basic  AuthType = "Basic"
	bearer AuthType = "Bearer"
	digest AuthType = "Digest"
)

// Config structure
type Config struct {
	tokenSource TokenSource `yaml:"tokenSource"`
	encodeToken bool        `yaml:"encodeToken"`
	sourceType  AuthType    `yaml:"sourceType"`
	targetType  AuthType    `yaml:"targetType"`
}

// Main struct
type AuthConverter struct {
	next   http.Handler
	config *Config
}

// Gets token from passed header
func (e *AuthConverter) getToken(header string) (string, error) {
	splitHeader := strings.SplitN(header, " ", 2)
	if len(splitHeader) != 2 {
		return "", errors.New("invalid authorization header contents")
	}
	if splitHeader[0] != string(e.config.sourceType) {
		return "", errors.New("invalid authorization type")
	}
	sourceTokenBase64 := splitHeader[1]

	if e.config.tokenSource == unchanged {
		return sourceTokenBase64, nil
	}

	sourceTokenDecoded, err := base64.StdEncoding.DecodeString(sourceTokenBase64)
	if err != nil {
		return "", errors.New("Base64 decoding failed")
	}

	if e.config.tokenSource == decoded {
		return string(sourceTokenDecoded), nil
	}

	if e.config.sourceType != basic {
		return "", errors.New("partial ")
	}
	basicTokenParts := strings.SplitN(string(sourceTokenDecoded), ":", 2)
	if len(basicTokenParts) != 2 {
		return "", errors.New("invalid value in authorization header")
	}

	switch e.config.tokenSource {
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
		if e.config.encodeToken {
			token = base64.StdEncoding.EncodeToString([]byte(token))
		}
		authorization := string(e.config.targetType) + " " + token
		req.Header.Set(HeaderName, authorization)
	}

	e.next.ServeHTTP(rw, req)
}

func CreateConfig() *Config {
	return &Config{
		tokenSource: combined,
		encodeToken: false,
		sourceType:  basic,
		targetType:  bearer,
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	validConfig := map[TokenSource]bool{username: true, password: true, unchanged: true, combined: true, decoded: true}
	if !validConfig[config.tokenSource] {
		return nil, errors.New("invalid token source")
	}

	return &AuthConverter{
		next:   next,
		config: config,
	}, nil
}
