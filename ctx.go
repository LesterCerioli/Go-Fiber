// ⚡️ Fiber is an Express inspired web framework written in Go with ☕️
// 🤖 Github Repository: https://github.com/gofiber/fiber
// 📌 API Documentation: https://docs.gofiber.io

package fiber

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"strconv"
	"time"

	"github.com/gofiber/utils/v2"
	"github.com/valyala/bytebufferpool"
	"github.com/valyala/fasthttp"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// maxParams defines the maximum number of parameters per route.
const maxParams = 30

// The contextKey type is unexported to prevent collisions with context keys defined in
// other packages.
type contextKey int

// userContextKey define the key name for storing context.Context in *fasthttp.RequestCtx
const userContextKey contextKey = 0 // __local_user_context__

type DefaultCtx struct {
	app          *App                 // Reference to *App
	req          Request              // Reference to *Request
	res          Response             // Reference to *Response
	indexRoute   int                  // Index of the current route
	indexHandler int                  // Index of the current handler
	fasthttp     *fasthttp.RequestCtx // Reference to *fasthttp.RequestCtx
	matched      bool                 // Non use route matched
	bind         *Bind                // Default bind reference
	redirect     *Redirect            // Default redirect reference
}

// TLSHandler object
type TLSHandler struct {
	clientHelloInfo *tls.ClientHelloInfo
}

// GetClientInfo Callback function to set ClientHelloInfo
// Must comply with the method structure of https://cs.opensource.google/go/go/+/refs/tags/go1.20:src/crypto/tls/common.go;l=554-563
// Since we overlay the method of the tls config in the listener method
func (t *TLSHandler) GetClientInfo(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.clientHelloInfo = info
	return nil, nil //nolint:nilnil // Not returning anything useful here is probably fine
}

// Range data for c.Range
type Range struct {
	Type   string
	Ranges []RangeSet
}

// RangeSet represents a single content range from a request.
type RangeSet struct {
	Start int
	End   int
}

// Cookie data for c.Cookie
type Cookie struct {
	Name        string    `json:"name"`
	Value       string    `json:"value"`
	Path        string    `json:"path"`
	Domain      string    `json:"domain"`
	MaxAge      int       `json:"max_age"`
	Expires     time.Time `json:"expires"`
	Secure      bool      `json:"secure"`
	HTTPOnly    bool      `json:"http_only"`
	SameSite    string    `json:"same_site"`
	SessionOnly bool      `json:"session_only"`
}

// Views is the interface that wraps the Render function.
type Views interface {
	Load() error
	Render(out io.Writer, name string, binding any, layout ...string) error
}

// Accepts is an alias of [Request.Accepts]
func (c *DefaultCtx) Accepts(offers ...string) string {
	return c.req.Accepts(offers...)
}

// AcceptsCharsets is an alias of [Request.AcceptsCharsets]
func (c *DefaultCtx) AcceptsCharsets(offers ...string) string {
	return c.req.AcceptsCharsets(offers...)
}

// AcceptsEncodings is an alias of [Request.AcceptsEncodings]
func (c *DefaultCtx) AcceptsEncodings(offers ...string) string {
	return c.req.AcceptsEncodings(offers...)
}

// AcceptsLanguages is an alias of [Request.AcceptsLanguages]
func (c *DefaultCtx) AcceptsLanguages(offers ...string) string {
	return c.req.AcceptsLanguages(offers...)
}

// App returns the *App reference to the instance of the Fiber application
func (c *DefaultCtx) App() *App {
	return c.app
}

// Append is an alias of [Response.Append].
func (c *DefaultCtx) Append(field string, values ...string) {
	c.res.Append(field, values...)
}

// Attachment is an alias of [Response.Attachment].
func (c *DefaultCtx) Attachment(filename ...string) {
	c.res.Attachment(filename...)
}

// BaseURL is an alias of [Request.BaseURL].
func (c *DefaultCtx) BaseURL() string {
	return c.req.BaseURL()
}

// BodyRaw is an alias of [Request.BodyRaw].
func (c *DefaultCtx) BodyRaw() []byte {
	return c.req.BodyRaw()
}

// Body is an alias of [Request.Body].
func (c *DefaultCtx) Body() []byte {
	return c.req.Body()
}

// ClearCookie is an alias of [Response.ClearCookie].
func (c *DefaultCtx) ClearCookie(key ...string) {
	c.res.ClearCookie(key...)
}

// Context returns *fasthttp.RequestCtx that carries a deadline
// a cancellation signal, and other values across API boundaries.
func (c *DefaultCtx) Context() *fasthttp.RequestCtx {
	return c.fasthttp
}

// UserContext returns a context implementation that was set by
// user earlier or returns a non-nil, empty context,if it was not set earlier.
func (c *DefaultCtx) UserContext() context.Context {
	ctx, ok := c.fasthttp.UserValue(userContextKey).(context.Context)
	if !ok {
		ctx = context.Background()
		c.SetUserContext(ctx)
	}

	return ctx
}

// SetUserContext sets a context implementation by user.
func (c *DefaultCtx) SetUserContext(ctx context.Context) {
	c.fasthttp.SetUserValue(userContextKey, ctx)
}

// Cookie is an alias of [Response.Cookie].
func (c *DefaultCtx) Cookie(cookie *Cookie) {
	c.res.Cookie(cookie)
}

// Cookies is an alias of [Request.Cookies]
func (c *DefaultCtx) Cookies(key string, defaultValue ...string) string {
	return c.req.Cookies(key, defaultValue...)
}

// Download is an alias of [Response.Download].
func (c *DefaultCtx) Download(file string, filename ...string) error {
	return c.res.Download(file, filename...)
}

// Req returns the Request object for the current context.
func (c *DefaultCtx) Req() *Request {
	return &c.req
}

// Res returns the Response object for the current context.
func (c *DefaultCtx) Res() *Response {
	return &c.res
}

// Response return the *fasthttp.Response object
// This allows you to use all fasthttp response methods
// https://godoc.org/github.com/valyala/fasthttp#Response
func (c *DefaultCtx) Response() *fasthttp.Response {
	return &c.fasthttp.Response
}

// Format is an alias of [Response.Format]
func (c *DefaultCtx) Format(handlers ...ResFmt) error {
	return c.res.Format(handlers...)
}

// AutoFormat performs content-negotiation on the Accept HTTP header.
// It uses Accepts to select a proper format.
// The supported content types are text/html, text/plain, application/json, and application/xml.
// For more flexible content negotiation, use Format.
// If the header is not specified or there is no proper format, text/plain is used.
func (c *DefaultCtx) AutoFormat(body any) error {
	// Get accepted content type
	accept := c.Accepts("html", "json", "txt", "xml")
	// Set accepted content type
	c.Type(accept)
	// Type convert provided body
	var b string
	switch val := body.(type) {
	case string:
		b = val
	case []byte:
		b = c.app.getString(val)
	default:
		b = fmt.Sprintf("%v", val)
	}

	// Format based on the accept content type
	switch accept {
	case "html":
		return c.SendString("<p>" + b + "</p>")
	case "json":
		return c.JSON(body)
	case "txt":
		return c.SendString(b)
	case "xml":
		return c.XML(body)
	}
	return c.SendString(b)
}

// FormFile returns the first file by key from a MultipartForm.
func (c *DefaultCtx) FormFile(key string) (*multipart.FileHeader, error) {
	return c.fasthttp.FormFile(key)
}

// FormValue returns the first value by key from a MultipartForm.
// Search is performed in QueryArgs, PostArgs, MultipartForm and FormFile in this particular order.
// Defaults to the empty string "" if the form value doesn't exist.
// If a default value is given, it will return that value if the form value does not exist.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *DefaultCtx) FormValue(key string, defaultValue ...string) string {
	return defaultString(c.app.getString(c.fasthttp.FormValue(key)), defaultValue)
}

// Fresh is an alias of [Request.Fresh]
func (c *DefaultCtx) Fresh() bool {
	return c.req.Fresh()
}

// Get is an alias of [Request.Get].
func (c *DefaultCtx) Get(key string, defaultValue ...string) string {
	return c.req.Get(key, defaultValue...)
}

// GetReqHeader returns the HTTP request header specified by filed.
// This function is generic and can handle differnet headers type values.
func GetReqHeader[V GenericType](c Ctx, key string, defaultValue ...V) V {
	var v V
	return genericParseType[V](c.Req().Get(key), v, defaultValue...)
}

// GetRespHeader is an alias of [Response.Get].
func (c *DefaultCtx) GetRespHeader(key string, defaultValue ...string) string {
	return c.res.Get(key, defaultValue...)
}

// GetRespHeaders returns the HTTP response headers.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *DefaultCtx) GetRespHeaders() map[string][]string {
	headers := make(map[string][]string)
	c.Response().Header.VisitAll(func(k, v []byte) {
		key := c.app.getString(k)
		headers[key] = append(headers[key], c.app.getString(v))
	})
	return headers
}

// GetReqHeaders returns the HTTP request headers.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *DefaultCtx) GetReqHeaders() map[string][]string {
	headers := make(map[string][]string)
	c.fasthttp.Request.Header.VisitAll(func(k, v []byte) {
		key := c.app.getString(k)
		headers[key] = append(headers[key], c.app.getString(v))
	})
	return headers
}

// Host is an alias of [Request.Host].
func (c *DefaultCtx) Host() string {
	return c.req.Host()
}

// Hostname is an alias of [Request.Hostname].
func (c *DefaultCtx) Hostname() string {
	return c.req.Hostname()
}

// Port is an alias of [Request.Port].
func (c *DefaultCtx) Port() string {
	return c.req.Port()
}

// IP is an alias of [Request.IP].
func (c *DefaultCtx) IP() string {
	return c.req.IP()
}

// IPs is an alias of [Request.IPs].
func (c *DefaultCtx) IPs() []string {
	return c.req.IPs()
}

// Is is an alias of [Request.Is].
func (c *DefaultCtx) Is(extension string) bool {
	return c.req.Is(extension)
}

// JSON is an alias of [Response.JSON].
func (c *DefaultCtx) JSON(data any, ctype ...string) error {
	return c.res.JSON(data, ctype...)
}

// JSONP is an alias of [Response.JSONP].
func (c *DefaultCtx) JSONP(data any, callback ...string) error {
	return c.res.JSONP(data, callback...)
}

// XML is an alias of [Response.XML].
func (c *DefaultCtx) XML(data any) error {
	return c.res.XML(data)
}

// Links is an alias of [Response.Links].
func (c *DefaultCtx) Links(link ...string) {
	c.res.Links(link...)
}

// Locals makes it possible to pass any values under keys scoped to the request
// and therefore available to all following routes that match the request.
func (c *DefaultCtx) Locals(key any, value ...any) any {
	if len(value) == 0 {
		return c.fasthttp.UserValue(key)
	}
	c.fasthttp.SetUserValue(key, value[0])
	return value[0]
}

// Locals function utilizing Go's generics feature.
// This function allows for manipulating and retrieving local values within a request context with a more specific data type.
func Locals[V any](c Ctx, key any, value ...V) V {
	var v V
	var ok bool
	if len(value) == 0 {
		v, ok = c.Locals(key).(V)
	} else {
		v, ok = c.Locals(key, value[0]).(V)
	}
	if !ok {
		return v // return zero of type V
	}
	return v
}

// Location is an alias of [Response.Location].
func (c *DefaultCtx) Location(path string) {
	c.res.Location(path)
}

// Method is an alias of [Request.Method].
func (c *DefaultCtx) Method(override ...string) string {
	return c.req.Method(override...)
}

// MultipartForm is an alias of [Request.MultipartForm].
func (c *DefaultCtx) MultipartForm() (*multipart.Form, error) {
	return c.req.MultipartForm()
}

// ClientHelloInfo return CHI from context
func (c *DefaultCtx) ClientHelloInfo() *tls.ClientHelloInfo {
	if c.app.tlsHandler != nil {
		return c.app.tlsHandler.clientHelloInfo
	}

	return nil
}

// Next executes the next method in the stack that matches the current route.
func (c *DefaultCtx) Next() error {
	// Increment handler index
	c.indexHandler++
	var err error
	// Did we execute all route handlers?
	if c.indexHandler < len(c.req.route.Handlers) {
		// Continue route stack
		err = c.req.route.Handlers[c.indexHandler](c)
	} else {
		// Continue handler stack
		if c.app.newCtxFunc != nil {
			_, err = c.app.nextCustom(c)
		} else {
			_, err = c.app.next(c)
		}
	}
	return err
}

// RestartRouting instead of going to the next handler. This may be useful after
// changing the request path. Note that handlers might be executed again.
func (c *DefaultCtx) RestartRouting() error {
	var err error

	c.indexRoute = -1
	if c.app.newCtxFunc != nil {
		_, err = c.app.nextCustom(c)
	} else {
		_, err = c.app.next(c)
	}
	return err
}

// OriginalURL is an alias of [Request.OriginalURL]
func (c *DefaultCtx) OriginalURL() string {
	return c.req.OriginalURL()
}

// Params is an alias of [Request.Params].
func (c *DefaultCtx) Params(key string, defaultValue ...string) string {
	return c.req.Params(key, defaultValue...)
}

// Params is used to get the route parameters.
// This function is generic and can handle differnet route parameters type values.
//
// Example:
//
// http://example.com/user/:user -> http://example.com/user/john
// Params[string](c, "user") -> returns john
//
// http://example.com/id/:id -> http://example.com/user/114
// Params[int](c, "id") ->  returns 114 as integer.
//
// http://example.com/id/:number -> http://example.com/id/john
// Params[int](c, "number", 0) -> returns 0 because can't parse 'john' as integer.
func Params[V GenericType](c Ctx, key string, defaultValue ...V) V {
	var v V
	return genericParseType(c.Params(key), v, defaultValue...)
}

// Path is an alias of [Request.Path].
func (c *DefaultCtx) Path(override ...string) string {
	return c.req.Path(override...)
}

// Scheme is an alias of [Request.Scheme].
func (c *DefaultCtx) Scheme() string {
	return c.req.Scheme()
}

// Protocol is an alias of [Request.Protocol].
func (c *DefaultCtx) Protocol() string {
	return c.req.Protocol()
}

// Query is an alias of [Request.Query].
func (c *DefaultCtx) Query(key string, defaultValue ...string) string {
	return c.req.Query(key, defaultValue...)
}

// Queries is an alias of [Request.Queries].
func (c *DefaultCtx) Queries() map[string]string {
	m := make(map[string]string, c.Context().QueryArgs().Len())
	c.Context().QueryArgs().VisitAll(func(key, value []byte) {
		m[c.app.getString(key)] = c.app.getString(value)
	})
	return m
}

// Query Retrieves the value of a query parameter from the request's URI.
// The function is generic and can handle query parameter values of different types.
// It takes the following parameters:
// - c: The context object representing the current request.
// - key: The name of the query parameter.
// - defaultValue: (Optional) The default value to return in case the query parameter is not found or cannot be parsed.
// The function performs the following steps:
//  1. Type-asserts the context object to *DefaultCtx.
//  2. Retrieves the raw query parameter value from the request's URI.
//  3. Parses the raw value into the appropriate type based on the generic type parameter V.
//     If parsing fails, the function checks if a default value is provided. If so, it returns the default value.
//  4. Returns the parsed value.
//
// If the generic type cannot be matched to a supported type, the function returns the default value (if provided) or the zero value of type V.
//
// Example usage:
//
//	GET /?search=john&age=8
//	name := Query[string](c, "search") // Returns "john"
//	age := Query[int](c, "age") // Returns 8
//	unknown := Query[string](c, "unknown", "default") // Returns "default" since the query parameter "unknown" is not found
func Query[V GenericType](c Ctx, key string, defaultValue ...V) V {
	var v V
	return genericParseType[V](c.Req().Query(key), v, defaultValue...)
}

// Range is an alias of [Request.Range].
func (c *DefaultCtx) Range(size int) (Range, error) {
	return c.req.Range(size)
}

// Redirect returns the Redirect reference.
// Use Redirect().Status() to set custom redirection status code.
// If status is not specified, status defaults to 302 Found.
// You can use Redirect().To(), Redirect().Route() and Redirect().Back() for redirection.
func (c *DefaultCtx) Redirect() *Redirect {
	if c.redirect == nil {
		c.redirect = AcquireRedirect()
		c.redirect.c = c
	}

	return c.redirect
}

// ViewBind is an alias of [Response.ViewBind].
func (c *DefaultCtx) ViewBind(vars Map) error {
	return c.res.ViewBind(vars)
}

// getLocationFromRoute get URL location from route using parameters
func (c *DefaultCtx) getLocationFromRoute(route Route, params Map) (string, error) {
	buf := bytebufferpool.Get()
	for _, segment := range route.routeParser.segs {
		if !segment.IsParam {
			_, err := buf.WriteString(segment.Const)
			if err != nil {
				return "", fmt.Errorf("failed to write string: %w", err)
			}
			continue
		}

		for key, val := range params {
			isSame := key == segment.ParamName || (!c.app.config.CaseSensitive && utils.EqualFold(key, segment.ParamName))
			isGreedy := segment.IsGreedy && len(key) == 1 && isInCharset(key[0], greedyParameters)
			if isSame || isGreedy {
				_, err := buf.WriteString(utils.ToString(val))
				if err != nil {
					return "", fmt.Errorf("failed to write string: %w", err)
				}
			}
		}
	}
	location := buf.String()
	// release buffer
	bytebufferpool.Put(buf)
	return location, nil
}

// GetRouteURL generates URLs to named routes, with parameters. URLs are relative, for example: "/user/1831"
func (c *DefaultCtx) GetRouteURL(routeName string, params Map) (string, error) {
	return c.getLocationFromRoute(c.App().GetRoute(routeName), params)
}

// Render is an alias of [Response.Render].
func (c *DefaultCtx) Render(name string, bind Map, layouts ...string) error {
	return c.res.Render(name, bind, layouts...)
}

// Route is an alias of [Request.Route].
func (c *DefaultCtx) Route() *Route {
	return c.req.Route()
}

// SaveFile saves any multipart file to disk.
func (*DefaultCtx) SaveFile(fileheader *multipart.FileHeader, path string) error {
	return fasthttp.SaveMultipartFile(fileheader, path)
}

// SaveFileToStorage saves any multipart file to an external storage system.
func (*DefaultCtx) SaveFileToStorage(fileheader *multipart.FileHeader, path string, storage Storage) error {
	file, err := fileheader.Open()
	if err != nil {
		return fmt.Errorf("failed to open: %w", err)
	}

	content, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read: %w", err)
	}

	if err := storage.Set(path, content, 0); err != nil {
		return fmt.Errorf("failed to store: %w", err)
	}

	return nil
}

// Secure is an alias of [Request.Secure].
func (c *DefaultCtx) Secure() bool {
	return c.req.Secure()
}

// Send is an alias of [Response.Send].
func (c *DefaultCtx) Send(body []byte) error {
	return c.res.Send(body)
}

// SendFile is an alias of [Response.SendFile].
func (c *DefaultCtx) SendFile(file string, compress ...bool) error {
	return c.res.SendFile(file, compress...)
}

// SendStatus is an alias of [Response.SendStatus].
func (c *DefaultCtx) SendStatus(status int) error {
	return c.res.SendStatus(status)
}

// SendString is an alias of [Response.SendString].
func (c *DefaultCtx) SendString(body string) error {
	return c.res.SendString(body)
}

// SendStream sets response body stream and optional body size.
func (c *DefaultCtx) SendStream(stream io.Reader, size ...int) error {
	if len(size) > 0 && size[0] >= 0 {
		c.fasthttp.Response.SetBodyStream(stream, size[0])
	} else {
		c.fasthttp.Response.SetBodyStream(stream, -1)
	}

	return nil
}

// Set is an alias of [Response.Set].
func (c *DefaultCtx) Set(key, val string) {
	c.res.Set(key, val)
}

// Subdomains is an alias of [Request.Subdomains].
func (c *DefaultCtx) Subdomains(offset ...int) []string {
	return c.req.Subdomains(offset...)
}

// Stale is an alias of [Request.Stale].
func (c *DefaultCtx) Stale() bool {
	return c.req.Stale()
}

// Status is an alias of [Response.Status].
// This method is chainable.
func (c *DefaultCtx) Status(status int) Ctx {
	c.res.Status(status)
	return c
}

// String returns unique string representation of the ctx.
//
// The returned value may be useful for logging.
func (c *DefaultCtx) String() string {
	// Get buffer from pool
	buf := bytebufferpool.Get()

	// Start with the ID, converting it to a hex string without fmt.Sprintf
	buf.WriteByte('#')
	// Convert ID to hexadecimal
	id := strconv.FormatUint(c.fasthttp.ID(), 16)
	// Pad with leading zeros to ensure 16 characters
	for i := 0; i < (16 - len(id)); i++ {
		buf.WriteByte('0')
	}
	buf.WriteString(id)
	buf.WriteString(" - ")

	// Add local and remote addresses directly
	buf.WriteString(c.fasthttp.LocalAddr().String())
	buf.WriteString(" <-> ")
	buf.WriteString(c.fasthttp.RemoteAddr().String())
	buf.WriteString(" - ")

	// Add method and URI
	buf.Write(c.fasthttp.Request.Header.Method())
	buf.WriteByte(' ')
	buf.Write(c.fasthttp.URI().FullURI())

	// Allocate string
	str := buf.String()

	// Reset buffer
	buf.Reset()
	bytebufferpool.Put(buf)

	return str
}

// Type is an alias of [Response.Type].
func (c *DefaultCtx) Type(extension string, charset ...string) Ctx {
	c.res.Type(extension, charset...)
	return c
}

// Vary is an alias of [Response.Vary].
func (c *DefaultCtx) Vary(fields ...string) {
	c.Append(HeaderVary, fields...)
}

// Write is an alias of [Response.Write].
func (c *DefaultCtx) Write(p []byte) (int, error) {
	c.fasthttp.Response.AppendBody(p)
	return len(p), nil
}

// Writef is an alias of [Response.Writef].
func (c *DefaultCtx) Writef(f string, a ...any) (int, error) {
	return c.res.Writef(f, a...)
}

// WriteString is an alias of [Response.WriteString].
func (c *DefaultCtx) WriteString(s string) (int, error) {
	return c.res.WriteString(s)
}

// XHR is an alis of [Request.XHR].
func (c *DefaultCtx) XHR() bool {
	return c.req.XHR()
}

// IsProxyTrusted checks trustworthiness of remote ip.
// If EnableTrustedProxyCheck false, it returns true
// IsProxyTrusted can check remote ip by proxy ranges and ip map.
func (c *DefaultCtx) IsProxyTrusted() bool {
	if !c.app.config.EnableTrustedProxyCheck {
		return true
	}

	ip := c.fasthttp.RemoteIP()

	if _, trusted := c.app.config.trustedProxiesMap[ip.String()]; trusted {
		return true
	}

	for _, ipNet := range c.app.config.trustedProxyRanges {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// IsFromLocal will return true if request came from local.
func (c *DefaultCtx) IsFromLocal() bool {
	return c.req.IsFromLocal()
}

// Bind You can bind body, cookie, headers etc. into the map, map slice, struct easily by using Binding method.
// It gives custom binding support, detailed binding options and more.
// Replacement of: BodyParser, ParamsParser, GetReqHeaders, GetRespHeaders, AllParams, QueryParser, ReqHeaderParser
func (c *DefaultCtx) Bind() *Bind {
	if c.bind == nil {
		c.bind = &Bind{
			ctx:    c,
			should: true,
		}
	}
	return c.bind
}

// Convert a string value to a specified type, handling errors and optional default values.
func Convert[T any](value string, convertor func(string) (T, error), defaultValue ...T) (T, error) {
	converted, err := convertor(value)
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0], nil
		}

		return converted, fmt.Errorf("failed to convert: %w", err)
	}

	return converted, nil
}
