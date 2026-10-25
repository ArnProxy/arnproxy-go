// Package arnproxy is a server-side client for the ARNPROXY customer API.
// It never places an order until writes are explicitly enabled by the caller.
package arnproxy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const Version = "1.1.1"
const BaseURL = "https://www.arnproxy.com/account/api/v1/"
const maxBytes = 2 * 1024 * 1024

//go:embed resources.json
var contractBytes []byte

type resourceSpec struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	Write        bool   `json:"write"`
	ProviderRead bool   `json:"provider_read"`
	Disabled     bool   `json:"disabled"`
	Idempotency  bool   `json:"idempotency"`
}

var resources = func() map[string]resourceSpec {
	var c struct {
		Base      string                  `json:"base"`
		Resources map[string]resourceSpec `json:"resources"`
	}
	if json.Unmarshal(contractBytes, &c) != nil || c.Base != BaseURL || len(c.Resources) != 77 {
		panic("ARNPROXY_CONTRACT_INVALID")
	}
	return c.Resources
}()
var keyPattern = regexp.MustCompile(`^(?:[A-Za-z0-9]{32}|arnp_[a-f0-9]{16}_[a-f0-9]{64})$`)
var operationPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,100}$`)
var idPattern = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
var requestPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)
var codePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,79}$`)

// APIError carries safe diagnostic metadata, never a key or raw response.
type APIError struct {
	Code              string
	HTTPStatus        int
	RequestID         string
	RetryAfterSeconds *int
	Uncertain         bool
}

func (e *APIError) Error() string   { return e.Code }
func failure(code string) *APIError { return &APIError{Code: code} }

// Options are client-side guards, not server-side account permissions.
type Options struct {
	AllowWrites        bool
	AllowProviderReads bool
	Timeout            time.Duration
}
type Client struct {
	apiKey  string
	options Options
	http    *http.Client
}

func (c *Client) String() string               { return "ARNPROXY Client(key=REDACTED)" }
func (c *Client) GoString() string             { return c.String() }
func (c *Client) MarshalJSON() ([]byte, error) { return nil, failure("SERIALIZATION_DISABLED") }

// New accepts zero or one Options value. Timeout defaults to 20 seconds.
func New(apiKey string, options ...Options) (*Client, error) {
	if !keyPattern.MatchString(apiKey) {
		return nil, failure("INVALID_KEY_FORMAT")
	}
	if len(options) > 1 {
		return nil, failure("INVALID_CLIENT_OPTIONS")
	}
	o := Options{Timeout: 20 * time.Second}
	if len(options) == 1 {
		o = options[0]
		if o.Timeout == 0 {
			o.Timeout = 20 * time.Second
		}
	}
	if o.Timeout < time.Second || o.Timeout > 60*time.Second {
		return nil, failure("INVALID_CLIENT_OPTIONS")
	}
	// No environment proxy, HTTP/2 replay or reused-connection retries. POST
	// bodies have no GetBody replay function. Exactly one SDK send is performed.
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: o.Timeout}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: o.Timeout, ResponseHeaderTimeout: o.Timeout, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	h := &http.Client{Transport: transport, Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{apiKey: apiKey, options: o, http: h}, nil
}

type Meta struct {
	RequestID string `json:"request_id"`
}

// Response retains the full envelope. Decode Data into a caller-owned type.
type Response struct {
	OK   bool            `json:"ok"`
	Data json.RawMessage `json:"data"`
	Meta Meta            `json:"meta"`
}

func (r *Response) DecodeData(target any) error {
	if json.Unmarshal(r.Data, target) != nil {
		return failure("DATA_DECODE_FAILED")
	}
	return nil
}
func (c *Client) Account(ctx context.Context) (*Response, error) {
	return c.Request(ctx, "account", nil, "")
}
func (c *Client) Capabilities(ctx context.Context) (*Response, error) {
	return c.Request(ctx, "capabilities", nil, "")
}

func scalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, utf8.ValidString(x)
	case bool:
		if x {
			return "1", true
		}
		return "0", true
	case int:
		return strconv.Itoa(x), true
	case int8:
		return strconv.FormatInt(int64(x), 10), true
	case int16:
		return strconv.FormatInt(int64(x), 10), true
	case int32:
		return strconv.FormatInt(int64(x), 10), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case uint:
		return strconv.FormatUint(uint64(x), 10), true
	case uint8:
		return strconv.FormatUint(uint64(x), 10), true
	case uint16:
		return strconv.FormatUint(uint64(x), 10), true
	case uint32:
		return strconv.FormatUint(uint64(x), 10), true
	case uint64:
		return strconv.FormatUint(x, 10), true
	case json.Number:
		if regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`).MatchString(string(x)) {
			return string(x), true
		}
	}
	return "", false
}
func jsonInput(v any, depth int) bool {
	if depth > 32 {
		return false
	}
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case string:
		return utf8.ValidString(x)
	case bool:
		return true
	case map[string]any:
		for k, item := range x {
			if !utf8.ValidString(k) || !jsonInput(item, depth+1) {
				return false
			}
		}
		return true
	case []any:
		for _, item := range x {
			if !jsonInput(item, depth+1) {
				return false
			}
		}
		return true
	case float64, float32:
		_, err := json.Marshal(x)
		return err == nil
	default:
		if _, ok := scalar(v); ok {
			return true
		}
		value := reflect.ValueOf(v)
		switch value.Kind() {
		case reflect.Slice, reflect.Array:
			for i := 0; i < value.Len(); i++ {
				if !jsonInput(value.Index(i).Interface(), depth+1) {
					return false
				}
			}
			return true
		case reflect.Map:
			if value.Type().Key().Kind() != reflect.String {
				return false
			}
			it := value.MapRange()
			for it.Next() {
				if !utf8.ValidString(it.Key().String()) || !jsonInput(it.Value().Interface(), depth+1) {
					return false
				}
			}
			return true
		}
		return false
	}
}

// Request uses a documented resource name, not an arbitrary URL. Keep the same
// operationKey when querying the status of an uncertain operation. No retry.
func (c *Client) Request(ctx context.Context, resource string, params map[string]any, operationKey string) (*Response, error) {
	spec, ok := resources[resource]
	if !ok {
		return nil, failure("UNKNOWN_RESOURCE")
	}
	if spec.Disabled {
		return nil, failure("DISABLED_RESOURCE")
	}
	if params == nil {
		params = map[string]any{}
	}
	p := make(map[string]any, len(params))
	for k, v := range params {
		if !utf8.ValidString(k) {
			return nil, failure("INVALID_PARAMETERS")
		}
		p[k] = v
	}
	if _, ok := p["resource"]; ok {
		return nil, failure("INVALID_PARAMETERS")
	}
	if spec.Write && !c.options.AllowWrites {
		return nil, failure("WRITES_DISABLED")
	}
	if spec.ProviderRead && !c.options.AllowProviderReads {
		return nil, failure("PROVIDER_READS_DISABLED")
	}
	if spec.Idempotency && !operationPattern.MatchString(operationKey) {
		return nil, failure("OPERATION_KEY_REQUIRED")
	}
	if !spec.Idempotency && operationKey != "" {
		return nil, failure("UNEXPECTED_OPERATION_KEY")
	}
	path := spec.Path
	if strings.Contains(path, "{id}") {
		id, valid := scalar(p["id"])
		_, isBool := p["id"].(bool)
		number, err := strconv.ParseInt(id, 10, 64)
		if !valid || isBool || err != nil || !idPattern.MatchString(id) || number > 2147483647 {
			return nil, failure("INVALID_ROUTE_ID")
		}
		path = strings.ReplaceAll(path, "{id}", id)
		delete(p, "id")
	}
	var body []byte
	if spec.Method == http.MethodGet {
		q := url.Values{}
		for k, v := range p {
			value, valid := scalar(v)
			if !valid {
				return nil, failure("INVALID_QUERY_VALUE")
			}
			q.Set(k, value)
		}
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
	} else {
		if !jsonInput(p, 0) {
			return nil, failure("INVALID_JSON_BODY")
		}
		var err error
		body, err = json.Marshal(p)
		if err != nil {
			return nil, failure("INVALID_JSON_BODY")
		}
		if len(body) > maxBytes {
			return nil, failure("REQUEST_TOO_LARGE")
		}
	}
	if ctx == nil {
		return nil, failure("INVALID_CLIENT_OPTIONS")
	}
	req, err := http.NewRequestWithContext(ctx, spec.Method, BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, failure("INVALID_PARAMETERS")
	}
	req.GetBody = nil
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ARNPROXY-Go/"+Version)
	if spec.Idempotency {
		req.Header.Set("Idempotency-Key", operationKey)
	}
	if spec.Method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, &APIError{Code: "TRANSPORT_ERROR", Uncertain: spec.Write}
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return nil, &APIError{Code: "REDIRECT_BLOCKED", HTTPStatus: res.StatusCode, Uncertain: spec.Write}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return nil, &APIError{Code: "TRANSPORT_ERROR", HTTPStatus: res.StatusCode, Uncertain: spec.Write}
	}
	if len(raw) > maxBytes {
		return nil, &APIError{Code: "RESPONSE_TOO_LARGE", HTTPStatus: res.StatusCode, Uncertain: spec.Write}
	}
	var retry *int
	if value := res.Header.Get("Retry-After"); regexp.MustCompile(`^[0-9]{1,5}$`).MatchString(value) {
		n, _ := strconv.Atoi(value)
		if n <= 86400 {
			retry = &n
		}
	}
	invalid := func() (*Response, error) {
		return nil, &APIError{Code: "INVALID_API_RESPONSE", HTTPStatus: res.StatusCode, RetryAfterSeconds: retry, Uncertain: spec.Write}
	}
	var envelope map[string]json.RawMessage
	if !utf8.Valid(raw) || json.Unmarshal(raw, &envelope) != nil || envelope == nil {
		return invalid()
	}
	var success bool
	var meta Meta
	if !bytes.Equal(envelope["ok"], []byte("true")) && !bytes.Equal(envelope["ok"], []byte("false")) {
		return invalid()
	}
	if json.Unmarshal(envelope["ok"], &success) != nil || json.Unmarshal(envelope["meta"], &meta) != nil || !requestPattern.MatchString(meta.RequestID) {
		return invalid()
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 || !success {
		var e struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(envelope["error"], &e)
		if !codePattern.MatchString(e.Code) {
			e.Code = "API_HTTP_ERROR"
		}
		return nil, &APIError{Code: e.Code, HTTPStatus: res.StatusCode, RequestID: meta.RequestID, RetryAfterSeconds: retry, Uncertain: spec.Write && res.StatusCode >= 500}
	}
	data, exists := envelope["data"]
	if !exists {
		return invalid()
	}
	return &Response{OK: true, Data: append([]byte(nil), data...), Meta: meta}, nil
}

// VerifyWebhook verifies original raw bytes. Deduplicate event IDs in your own
// durable store; a valid signature does not imply operation completion.
func VerifyWebhook(raw []byte, headers map[string]string, signingSecret string, now time.Time) (map[string]any, error) {
	fail := func() (map[string]any, error) { return nil, failure("WEBHOOK_VERIFICATION_FAILED") }
	if len(raw) > 4096 || !utf8.Valid(raw) {
		return fail()
	}
	values := map[string]string{}
	for k, v := range headers {
		k = strings.ToLower(k)
		if k == "webhook-id" || k == "webhook-timestamp" || k == "webhook-signature" {
			if _, exists := values[k]; exists {
				return fail()
			}
			values[k] = v
		}
	}
	id, ts, sig := values["webhook-id"], values["webhook-timestamp"], values["webhook-signature"]
	if !regexp.MustCompile(`^evt_[a-f0-9]{32}$`).MatchString(id) || !regexp.MustCompile(`^[1-9][0-9]{0,11}$`).MatchString(ts) || len(sig) > 1024 || now.Unix() < 1 || now.Unix() > 999999999999 {
		return fail()
	}
	stamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || now.Unix()-stamp > 300 || stamp-now.Unix() > 300 {
		return fail()
	}
	if !regexp.MustCompile(`^whsec_[A-Za-z0-9+/]{43}=$`).MatchString(signingSecret) {
		return fail()
	}
	secret, err := base64.StdEncoding.DecodeString(signingSecret[6:])
	if err != nil || len(secret) != 32 || base64.StdEncoding.EncodeToString(secret) != signingSecret[6:] {
		return fail()
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(id + "." + ts + "."))
	_, _ = mac.Write(raw)
	expected := mac.Sum(nil)
	valid := false
	for _, token := range strings.Fields(sig) {
		if !regexp.MustCompile(`^v1,[A-Za-z0-9+/]{43}=$`).MatchString(token) {
			continue
		}
		actual, e := base64.StdEncoding.DecodeString(token[3:])
		if e == nil && hmac.Equal(expected, actual) {
			valid = true
		}
	}
	if !valid {
		return fail()
	}
	var event map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&event) != nil || event == nil || event["id"] != id || event["api_version"] != "1" {
		return fail()
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return fail()
	}
	if _, ok := event["data"].(map[string]any); !ok {
		return fail()
	}
	if _, ok := event["type"].(string); !ok {
		return fail()
	}
	return event, nil
}

// Deliberately no key in debugging output. Avoid logging Response values too:
// some API resources contain customer proxy connection passwords.
var _ fmt.Stringer = (*Client)(nil)
