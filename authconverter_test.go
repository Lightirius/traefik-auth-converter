package traefik_auth_converter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_ServeHTTP(t *testing.T) {

	var tests = []struct {
		name        string
		inputConfig Config
		inputHeader string
		expected    string
	}{
		{
			"Header should not be set whet token is not found",
			Config{tokenSource: password, encodeToken: false},
			"Bearer YTtkbmdhb3VpcmduYXdvZ2lu",
			"",
		},
		{
			"Header should be set for correct input headers",
			Config{tokenSource: combined, encodeToken: false},
			"Basic ZFhObGNsOXNiMmRwYm5WOnpaWEpmY0dGemMzZHZjbVE9",
			"Bearer dXNlcl9sb2dpbnVzZXJfcGFzc3dvcmQ=",
		},
		{
			"Token should be base64 encoded if requested",
			Config{tokenSource: combined, encodeToken: true},
			"Basic dXNlcl9sb2dpbjp1c2VyX3Bhc3N3b3Jk",
			"Bearer dXNlcl9sb2dpbnVzZXJfcGFzc3dvcmQ=",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			request.Header.Add("Authorization", testCase.inputHeader)

			authconverter, _ := New(ctx, next, &testCase.inputConfig, "")

			authconverter.ServeHTTP(recorder, request)
			actual := recorder.Result().Header.Get("Authorization")
			if actual != testCase.expected {
				t.Errorf("Expected: '%s', got: '%s'", testCase.expected, actual)
			}
		})
	}
}

func Test_New(t *testing.T) {

	var tests = []struct {
		name                string
		inputConfig         Config
		expectedTokenSource TokenSource
		expectedEncodeToken bool
		expectedError       bool
	}{
		{
			"Values from config should be set to object",
			Config{tokenSource: password, encodeToken: true},
			password,
			true,
			false,
		},
		{
			"Invalid config should return error",
			Config{tokenSource: "not_a_source", encodeToken: true},
			"",
			false,
			true,
		},
		{
			"Username type is allowed",
			Config{tokenSource: username, encodeToken: false},
			username,
			false,
			true,
		},
		{
			"Password type is allowed",
			Config{tokenSource: password, encodeToken: false},
			password,
			false,
			true,
		},
		{
			"Combined type is allowed",
			Config{tokenSource: combined, encodeToken: false},
			combined,
			false,
			true,
		},
		{
			"Unchanged type is allowed",
			Config{tokenSource: unchanged, encodeToken: false},
			unchanged,
			false,
			true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := New(context.TODO(), nil, &testCase.inputConfig, "")

			if err != nil {
				if !testCase.expectedError {
					t.Errorf(
						"Expected: '%s' '%t', got error: '%s'",
						testCase.expectedTokenSource,
						testCase.expectedEncodeToken,
						err,
					)
				}
				return
			}
			actualConverter := actual.(*AuthConverter)

			if actualConverter.tokenSource != testCase.expectedTokenSource {
				t.Errorf("Expected: '%s', got: '%s'", testCase.expectedTokenSource, actualConverter.tokenSource)
			}
			if actualConverter.encodeToken != testCase.expectedEncodeToken {
				t.Errorf("Expected: '%t', got: '%t'", testCase.expectedEncodeToken, actualConverter.encodeToken)
			}
		})
	}
}

func Test_getToken(t *testing.T) {

	var tests = []struct {
		name          string
		inputHeader   string
		inputSource   TokenSource
		expected      string
		expectedError bool
	}{
		{"Bearer auth should return error", "Bearer YTtkbmdhb3VpcmduYXdvZ2lu", password, "", true},
		{"Digest auth should return error", "Digest YTtkbmdhb3VpcmduYXdvZ2lu", password, "", true},
		{"Invalid header value should return error", "BearerYTtkbmdhb3VpcmduYXdvZ2lu", password, "", true},
		{"Missing colon in token should return error", "Basic dXNlcl9sb2dpbnVzZXJfcGFzc3dvcmQ=", password, "", true},
		{"Invalid base64 string should return error", "Basic dXNlcl9sb2dpbjp1c2VyX3Bhc3N3b3Jk-", password, "", true},
		{"Invalid token source should return error", "Basic dXNlcl9sb2dpbjp1c2VyX3Bhc3N3b3Jk-", "not_a_source", "", true},
		{"When the source is 'password' token should be returned from password",
			"Basic dXNlcl9sb2dpbjp1c2VyX3Bhc3N3b3Jk",
			password,
			"user_password",
			true,
		},
		{
			"When the source is 'username' token should be returned from username",
			"Basic dXNlcl9sb2dpbjp1c2VyX3Bhc3N3b3Jk",
			username,
			"user_login",
			true,
		},
		{
			"When the source is 'unchanged' token should be unchanged base64 string",
			"Basic YTtkbmdhb3VpcmduYXdvZ2lu",
			unchanged,
			"YTtkbmdhb3VpcmduYXdvZ2lu",
			true,
		},
		{
			"When the source is 'combined' token should be a combination of username and password",
			"Basic YTtkbmdhb3VpcmduYXdvZ2lu",
			combined,
			"user_loginuser_password",
			true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			converter := AuthConverter{
				next:        nil,
				tokenSource: testCase.inputSource,
				encodeToken: false,
			}

			actual, err := converter.getToken(testCase.inputHeader)
			if err != nil {
				if !testCase.expectedError {
					t.Errorf("Expected: '%s', got error: '%s'", testCase.expected, err)
				}
				return
			}
			if actual != testCase.expected {
				t.Errorf("Expected: '%s', got: '%s'", testCase.expected, actual)
			}
		})
	}
}
