package arnproxy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const testKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testOperation = "op_synthetic_1234567890"
const successBody = `{"ok":true,"data":{"id":2},"meta":{"request_id":"aaaaaaaaaaaaaaaaaaaaaaaa"}}`

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func mock(t *testing.T, o Options, fn roundTrip) *Client {
	t.Helper()
	c, e := New(testKey, o)
	if e != nil {
		t.Fatal(e)
	}
	c.http.Transport = fn
	return c
}
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}
func expect(t *testing.T, err error, code string) *APIError {
	t.Helper()
	var e *APIError
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("expected %s got %v", code, err)
	}
	if strings.Contains(e.Error(), testKey) {
		t.Fatal("secret in error")
	}
	return e
}
func TestAllResources(t *testing.T) {
	for name, spec := range resources {
		t.Run(name, func(t *testing.T) {
			calls := 0
			p := map[string]any{"q": "ü & = ? /"}
			if strings.Contains(spec.Path, "{id}") {
				p["id"] = 123
			}
			key := ""
			if spec.Idempotency {
				key = testOperation
			}
			c := mock(t, Options{AllowWrites: true, AllowProviderReads: true}, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != spec.Method || r.URL.Path != "/account/api/v1/"+strings.ReplaceAll(spec.Path, "{id}", "123") || r.URL.Host != "www.arnproxy.com" {
					t.Fatal("route")
				}
				if r.Header.Get("Authorization") != "Bearer "+testKey || r.Header.Get("Idempotency-Key") != key || strings.Contains(r.URL.String(), testKey) || r.GetBody != nil {
					t.Fatal("headers or replay")
				}
				if r.Method == "GET" {
					if r.URL.Query().Get("q") != p["q"] {
						t.Fatal("query")
					}
				} else {
					var body map[string]any
					if json.NewDecoder(r.Body).Decode(&body) != nil || body["q"] != p["q"] {
						t.Fatal("body")
					}
				}
				return response(200, successBody), nil
			})
			result, err := c.Request(context.Background(), name, p, key)
			if spec.Disabled {
				expect(t, err, "DISABLED_RESOURCE")
				if calls != 0 {
					t.Fatal("disabled sent")
				}
				return
			}
			if err != nil || !result.OK || calls != 1 {
				t.Fatal("request", err)
			}
			var account struct{ ID int }
			if result.DecodeData(&account) != nil || account.ID != 2 {
				t.Fatal("data")
			}
			if _, ok := p["id"]; strings.Contains(spec.Path, "{id}") && !ok {
				t.Fatal("input mutated")
			}
			guarded := mock(t, Options{}, func(*http.Request) (*http.Response, error) { t.Fatal("guard sent"); return nil, nil })
			if spec.Write || spec.ProviderRead {
				_, err = guarded.Request(context.Background(), name, p, key)
				code := "PROVIDER_READS_DISABLED"
				if spec.Write {
					code = "WRITES_DISABLED"
				}
				expect(t, err, code)
			}
			if spec.Idempotency {
				_, err = c.Request(context.Background(), name, p, "")
				expect(t, err, "OPERATION_KEY_REQUIRED")
				if calls != 1 {
					t.Fatal("guard repeated")
				}
			}
		})
	}
}
func TestValidationAndErrors(t *testing.T) {
	for _, key := range []string{"", testKey + "\n", " " + testKey, strings.Repeat("x", 31)} {
		_, e := New(key)
		expect(t, e, "INVALID_KEY_FORMAT")
	}
	_, e := New(testKey, Options{Timeout: time.Millisecond})
	expect(t, e, "INVALID_CLIENT_OPTIONS")
	calls := 0
	status, body, retry := 200, successBody, ""
	failure := false
	c := mock(t, Options{AllowWrites: true, AllowProviderReads: true}, func(*http.Request) (*http.Response, error) {
		calls++
		if failure {
			return nil, errors.New("secret " + testKey)
		}
		r := response(status, body)
		r.Header.Set("Retry-After", retry)
		return r, nil
	})
	tests := []struct {
		resource  string
		p         map[string]any
		key, code string
	}{
		{"missing", nil, "", "UNKNOWN_RESOURCE"}, {"account", map[string]any{"resource": "purchase"}, "", "INVALID_PARAMETERS"}, {"proxy", map[string]any{"id": "1/../../secret"}, "", "INVALID_ROUTE_ID"}, {"proxy", map[string]any{"id": true}, "", "INVALID_ROUTE_ID"}, {"orders", map[string]any{"q": []int{1, 2}}, "", "INVALID_QUERY_VALUE"}, {"quote", map[string]any{"n": math.NaN()}, "", "INVALID_JSON_BODY"}, {"quote", map[string]any{"x": strings.Repeat("x", maxBytes)}, "", "REQUEST_TOO_LARGE"}, {"account", nil, testOperation, "UNEXPECTED_OPERATION_KEY"}}
	for _, test := range tests {
		_, e := c.Request(context.Background(), test.resource, test.p, test.key)
		expect(t, e, test.code)
	}
	if calls != 0 {
		t.Fatal("invalid requests sent")
	}
	status, body = 302, ""
	_, e = c.Account(context.Background())
	if expect(t, e, "REDIRECT_BLOCKED").Uncertain {
		t.Fatal("read uncertain")
	}
	if calls != 1 {
		t.Fatal("retry")
	}
	status, body, retry = 429, `{"ok":false,"error":{"code":"RATE_LIMITED"},"meta":{"request_id":"aaaaaaaaaaaaaaaaaaaaaaaa"}}`, "12"
	_, e = c.Account(context.Background())
	api := expect(t, e, "RATE_LIMITED")
	if api.RetryAfterSeconds == nil || *api.RetryAfterSeconds != 12 || api.HTTPStatus != 429 || api.RequestID == "" {
		t.Fatal("error metadata")
	}
	status, body = 500, "<html>secret</html>"
	_, e = c.Request(context.Background(), "purchase", nil, testOperation)
	if !expect(t, e, "INVALID_API_RESPONSE").Uncertain {
		t.Fatal("write uncertainty")
	}
	failure = true
	before := calls
	_, e = c.Request(context.Background(), "purchase", nil, testOperation)
	if !expect(t, e, "TRANSPORT_ERROR").Uncertain || calls != before+1 {
		t.Fatal("transport retry")
	}
	failure = false
	status = 200
	for _, bad := range []string{`{"ok":"true","data":{},"meta":{"request_id":"aaaaaaaaaaaaaaaaaaaaaaaa"}}`, successBody + " {}", `{"ok":true,"meta":{"request_id":"aaaaaaaaaaaaaaaaaaaaaaaa"}}`, strings.Repeat("x", maxBytes+1)} {
		body = bad
		_, e = c.Account(context.Background())
		if e == nil {
			t.Fatal("malformed accepted")
		}
	}
	body = successBody
	_, e = c.Request(context.Background(), "quote", map[string]any{"ids": []int{1, 2}}, "")
	if e != nil {
		t.Fatal("typed slice", e)
	}
	if strings.Contains(fmt.Sprintf("%#v", c), testKey) {
		t.Fatal("debug key")
	}
	if _, e = json.Marshal(c); e == nil {
		t.Fatal("serialized key client")
	}
	transport := c.http.Transport
	_ = transport
	plain, _ := New(testKey)
	tr := plain.http.Transport.(*http.Transport)
	if tr.Proxy != nil || !tr.DisableKeepAlives || !tr.DisableCompression || tr.TLSClientConfig.InsecureSkipVerify || tr.ForceAttemptHTTP2 {
		t.Fatal("unsafe transport")
	}
}
func TestWebhookVectors(t *testing.T) {
	raw, e := os.ReadFile("testdata/fixtures.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixtures struct {
		Vectors []struct {
			Name, Body, Secret string
			SecretFixture      string `json:"secret_fixture"`
			Headers            map[string]string
			Now                int64
			Valid              bool
		}
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		t.Fatal("fixtures")
	}
	// Only deterministic, publicly documented test bytes. No live credentials.
	for i := range fixtures.Vectors {
		vector := &fixtures.Vectors[i]
		if vector.SecretFixture != "" {
			if vector.SecretFixture != "repeat_X_32" && vector.SecretFixture != "repeat_Y_32" {
				t.Fatal("INVALID_TEST_FIXTURE")
			}
			char := byte('X')
			if vector.SecretFixture == "repeat_Y_32" {
				char = 'Y'
			}
			vector.Secret = "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{char}, 32))
		}
	}

	for _, v := range fixtures.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			event, e := VerifyWebhook([]byte(v.Body), v.Headers, v.Secret, time.Unix(v.Now, 0))
			if (e == nil) != v.Valid {
				t.Fatal("vector", e)
			}
			if e == nil && event["id"] == nil {
				t.Fatal("event")
			}
		})
	}
	v := fixtures.Vectors[0]
	body := []byte(v.Body + " {}")
	key, _ := base64.StdEncoding.DecodeString(v.Secret[6:])
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(v.Headers["webhook-id"] + "." + v.Headers["webhook-timestamp"] + "."))
	mac.Write(body)
	v.Headers["webhook-signature"] = "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	_, e = VerifyWebhook(body, v.Headers, v.Secret, time.Unix(v.Now, 0))
	expect(t, e, "WEBHOOK_VERIFICATION_FAILED")
	// Integer payload values must not be silently converted to float64.
	body = bytes.ReplaceAll([]byte(v.Body), []byte(`"account_id":2`), []byte(`"account_id":9007199254740993`))
	mac.Reset()
	mac.Write([]byte(v.Headers["webhook-id"] + "." + v.Headers["webhook-timestamp"] + "."))
	mac.Write(body)
	v.Headers["webhook-signature"] = "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	event, e := VerifyWebhook(body, v.Headers, v.Secret, time.Unix(v.Now, 0))
	if e != nil || event["data"].(map[string]any)["account_id"].(json.Number).String() != "9007199254740993" {
		t.Fatal("integer precision")
	}
}
