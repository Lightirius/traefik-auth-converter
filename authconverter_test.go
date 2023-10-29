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
			"Header should not be changed when token is not found",
			Config{tokenSource: combined, encodeToken: false, sourceType: basic, targetType: bearer},
			"Bearer YTtkbmdhb3VpcmduYXdvZ2lu",
			"Bearer YTtkbmdhb3VpcmduYXdvZ2lu",
		},
		{
			"Header should be set for correct target type",
			Config{tokenSource: combined, encodeToken: false, sourceType: basic, targetType: bearer},
			"Basic ZFhObGNsOXNiMmRwYm5WOnpaWEpmY0dGemMzZHZjbVE9",
			"Bearer dXNlcl9sb2dpbnVzZXJfcGFzc3dvcmQ=",
		},
		{
			"Header should be set for correct target type",
			Config{tokenSource: combined, encodeToken: false, sourceType: basic, targetType: digest},
			"Basic ZFhObGNsOXNiMmRwYm5WOnpaWEpmY0dGemMzZHZjbVE9",
			"Digest dXNlcl9sb2dpbnVzZXJfcGFzc3dvcmQ=",
		},
		{
			"Token should be base64 encoded if requested",
			Config{tokenSource: combined, encodeToken: true, sourceType: basic, targetType: bearer},
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
			actual := request.Header.Get("Authorization")
			if actual != testCase.expected {
				t.Errorf("Expected: '%s', got: '%s'", testCase.expected, actual)
			}
		})
	}
}

func Test_New(t *testing.T) {

	var tests = []struct {
		name           string
		inputConfig    Config
		expectedConfig Config
		expectedError  bool
	}{
		{
			"Values from config should be set to object",
			Config{tokenSource: password, encodeToken: true, sourceType: bearer, targetType: digest},
			Config{tokenSource: password, encodeToken: true, sourceType: bearer, targetType: digest},
			false,
		},
		{
			"Invalid source should return error",
			Config{tokenSource: "not_a_source", encodeToken: true},
			Config{tokenSource: "not_a_source", encodeToken: true},
			true,
		},
		{
			"Username type is allowed",
			Config{tokenSource: username, encodeToken: false},
			Config{tokenSource: username, encodeToken: false},
			false,
		},
		{
			"Password type is allowed",
			Config{tokenSource: password, encodeToken: false},
			Config{tokenSource: password, encodeToken: false},
			false,
		},
		{
			"Combined type is allowed",
			Config{tokenSource: combined, encodeToken: false},
			Config{tokenSource: combined, encodeToken: false},
			false,
		},
		{
			"Unchanged type is allowed",
			Config{tokenSource: unchanged, encodeToken: false},
			Config{tokenSource: unchanged, encodeToken: false},
			false,
		},
		{
			"Decoded type is allowed",
			Config{tokenSource: decoded, encodeToken: false},
			Config{tokenSource: decoded, encodeToken: false},
			false,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := New(context.TODO(), nil, &testCase.inputConfig, "")

			if err != nil {
				if testCase.expectedError {
					return //Expected error - got one
				} else {
					//Not expected error - got one
					t.Errorf(
						"Expected: '%vf', got error: '%s'",
						testCase.expectedConfig,
						err,
					)
				}
			} else {
				if testCase.expectedError {
					//Expected error - but there is no error
					t.Errorf(
						"Expected error, got: '%vf'",
						actual,
					)
				} else {
					//Not expected error - got no errors
					actualConverter := actual.(*AuthConverter)

					if *actualConverter.config != testCase.expectedConfig {
						t.Errorf("Expected: '%vf', got: '%vf'", testCase.expectedConfig, *actualConverter.config)
					}
				}
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
		{
			"When the source is 'decoded' token should be a decoded original token",
			"Basic YTtkbmdhb3VpcmduYXdvZ2lu",
			decoded,
			"a;dngaouirgnawogin",
			true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			converter := AuthConverter{
				next: nil,
				config: &Config{
					tokenSource: testCase.inputSource,
					encodeToken: false,
					sourceType:  basic,
					targetType:  bearer,
				},
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
