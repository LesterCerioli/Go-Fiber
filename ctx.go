// ⚡️ Fiber is an Express inspired web framework written in Go with ☕️
// 🤖 Github Repository: https://github.com/gofiber/fiber
// 📌 API Documentation: https://docs.gofiber.io

package fiber

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/template"
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
	app *App    // Reference to *App
	req Request // Reference to *Request
	// res				*Response // Reference to *Response
	indexRoute          int                  // Index of the current route
	indexHandler        int                  // Index of the current handler
	fasthttp            *fasthttp.RequestCtx // Reference to *fasthttp.RequestCtx
	matched             bool                 // Non use route matched
	viewBindMap         sync.Map             // Default view map to bind template engine
	bind                *Bind                // Default bind reference
	redirect            *Redirect            // Default redirect reference
	redirectionMessages []string             // Messages of the previous redirect
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

// ResFmt associates a Content Type to a fiber.Handler for c.Format
type ResFmt struct {
	MediaType string
	Handler   func(Ctx) error
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

// Append the specified value to the HTTP response header field.
// If the header is not already set, it creates the header with the specified value.
func (c *DefaultCtx) Append(field string, values ...string) {
	if len(values) == 0 {
		return
	}
	h := c.app.getString(c.fasthttp.Response.Header.Peek(field))
	originalH := h
	for _, value := range values {
		if len(h) == 0 {
			h = value
		} else if h != value && !strings.HasPrefix(h, value+",") && !strings.HasSuffix(h, " "+value) &&
			!strings.Contains(h, " "+value+",") {
			h += ", " + value
		}
	}
	if originalH != h {
		c.Set(field, h)
	}
}

// Attachment sets the HTTP response Content-Disposition header field to attachment.
func (c *DefaultCtx) Attachment(filename ...string) {
	if len(filename) > 0 {
		fname := filepath.Base(filename[0])
		c.Type(filepath.Ext(fname))

		c.setCanonical(HeaderContentDisposition, `attachment; filename="`+c.app.quoteString(fname)+`"`)
		return
	}
	c.setCanonical(HeaderContentDisposition, "attachment")
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

// ClearCookie expires a specific cookie by key on the client side.
// If no key is provided it expires all cookies that came with the request.
func (c *DefaultCtx) ClearCookie(key ...string) {
	if len(key) > 0 {
		for i := range key {
			c.fasthttp.Response.Header.DelClientCookie(key[i])
		}
		return
	}
	c.fasthttp.Request.Header.VisitAllCookie(func(k, _ []byte) {
		c.fasthttp.Response.Header.DelClientCookieBytes(k)
	})
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

// Cookie sets a cookie by passing a cookie struct.
func (c *DefaultCtx) Cookie(cookie *Cookie) {
	fcookie := fasthttp.AcquireCookie()
	fcookie.SetKey(cookie.Name)
	fcookie.SetValue(cookie.Value)
	fcookie.SetPath(cookie.Path)
	fcookie.SetDomain(cookie.Domain)
	// only set max age and expiry when SessionOnly is false
	// i.e. cookie supposed to last beyond browser session
	// refer: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define_the_lifetime_of_a_cookie
	if !cookie.SessionOnly {
		fcookie.SetMaxAge(cookie.MaxAge)
		fcookie.SetExpire(cookie.Expires)
	}
	fcookie.SetSecure(cookie.Secure)
	fcookie.SetHTTPOnly(cookie.HTTPOnly)

	switch utils.ToLower(cookie.SameSite) {
	case CookieSameSiteStrictMode:
		fcookie.SetSameSite(fasthttp.CookieSameSiteStrictMode)
	case CookieSameSiteNoneMode:
		fcookie.SetSameSite(fasthttp.CookieSameSiteNoneMode)
	case CookieSameSiteDisabled:
		fcookie.SetSameSite(fasthttp.CookieSameSiteDisabled)
	default:
		fcookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	}

	c.fasthttp.Response.Header.SetCookie(fcookie)
	fasthttp.ReleaseCookie(fcookie)
}

// Cookies is an alias of [Request.Cookies]
func (c *DefaultCtx) Cookies(key string, defaultValue ...string) string {
	return c.req.Cookies(key, defaultValue...)
}

// Download transfers the file from path as an attachment.
// Typically, browsers will prompt the user for download.
// By default, the Content-Disposition header filename= parameter is the filepath (this typically appears in the browser dialog).
// Override this default with the filename parameter.
func (c *DefaultCtx) Download(file string, filename ...string) error {
	var fname string
	if len(filename) > 0 {
		fname = filename[0]
	} else {
		fname = filepath.Base(file)
	}
	c.setCanonical(HeaderContentDisposition, `attachment; filename="`+c.app.quoteString(fname)+`"`)
	return c.SendFile(file)
}

// Req return the *fasthttp.Req object
// This allows you to use all fasthttp request methods
// https://godoc.org/github.com/valyala/fasthttp#Req
func (c *DefaultCtx) Req() *Request {
	return &c.req
}

// Response return the *fasthttp.Response object
// This allows you to use all fasthttp response methods
// https://godoc.org/github.com/valyala/fasthttp#Response
func (c *DefaultCtx) Response() *fasthttp.Response {
	return &c.fasthttp.Response
}

// Format performs content-negotiation on the Accept HTTP header.
// It uses Accepts to select a proper format and calls the matching
// user-provided handler function.
// If no accepted format is found, and a format with MediaType "default" is given,
// that default handler is called. If no format is found and no default is given,
// StatusNotAcceptable is sent.
func (c *DefaultCtx) Format(handlers ...ResFmt) error {
	if len(handlers) == 0 {
		return ErrNoHandlers
	}

	c.Vary(HeaderAccept)

	if c.Get(HeaderAccept) == "" {
		c.Response().Header.SetContentType(handlers[0].MediaType)
		return handlers[0].Handler(c)
	}

	// Using an int literal as the slice capacity allows for the slice to be
	// allocated on the stack. The number was chosen arbitrarily as an
	// approximation of the maximum number of content types a user might handle.
	// If the user goes over, it just causes allocations, so it's not a problem.
	types := make([]string, 0, 8)
	var defaultHandler Handler
	for _, h := range handlers {
		if h.MediaType == "default" {
			defaultHandler = h.Handler
			continue
		}
		types = append(types, h.MediaType)
	}
	accept := c.Accepts(types...)

	if accept == "" {
		if defaultHandler == nil {
			return c.SendStatus(StatusNotAcceptable)
		}
		return defaultHandler(c)
	}

	for _, h := range handlers {
		if h.MediaType == accept {
			c.Response().Header.SetContentType(h.MediaType)
			return h.Handler(c)
		}
	}

	return fmt.Errorf("%w: format: an Accept was found but no handler was called", errUnreachable)
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

// GetRespHeader returns the HTTP response header specified by field.
// Field names are case-insensitive
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *DefaultCtx) GetRespHeader(key string, defaultValue ...string) string {
	return defaultString(c.app.getString(c.fasthttp.Response.Header.Peek(key)), defaultValue)
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

// Port returns the remote port of the request.
func (c *DefaultCtx) Port() string {
	tcpaddr, ok := c.fasthttp.RemoteAddr().(*net.TCPAddr)
	if !ok {
		panic(errors.New("failed to type-assert to *net.TCPAddr"))
	}
	return strconv.Itoa(tcpaddr.Port)
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

// JSON converts any interface or string to JSON.
// Array and slice values encode as JSON arrays,
// except that []byte encodes as a base64-encoded string,
// and a nil slice encodes as the null JSON value.
// If the ctype parameter is given, this method will set the
// Content-Type header equal to ctype. If ctype is not given,
// The Content-Type header will be set to application/json.
func (c *DefaultCtx) JSON(data any, ctype ...string) error {
	raw, err := c.app.config.JSONEncoder(data)
	if err != nil {
		return err
	}
	c.fasthttp.Response.SetBodyRaw(raw)
	if len(ctype) > 0 {
		c.fasthttp.Response.Header.SetContentType(ctype[0])
	} else {
		c.fasthttp.Response.Header.SetContentType(MIMEApplicationJSON)
	}
	return nil
}

// JSONP sends a JSON response with JSONP support.
// This method is identical to JSON, except that it opts-in to JSONP callback support.
// By default, the callback name is simply callback.
func (c *DefaultCtx) JSONP(data any, callback ...string) error {
	raw, err := c.app.config.JSONEncoder(data)
	if err != nil {
		return err
	}

	var result, cb string

	if len(callback) > 0 {
		cb = callback[0]
	} else {
		cb = "callback"
	}

	result = cb + "(" + c.app.getString(raw) + ");"

	c.setCanonical(HeaderXContentTypeOptions, "nosniff")
	c.fasthttp.Response.Header.SetContentType(MIMETextJavaScriptCharsetUTF8)
	return c.SendString(result)
}

// XML converts any interface or string to XML.
// This method also sets the content header to application/xml.
func (c *DefaultCtx) XML(data any) error {
	raw, err := c.app.config.XMLEncoder(data)
	if err != nil {
		return err
	}
	c.fasthttp.Response.SetBodyRaw(raw)
	c.fasthttp.Response.Header.SetContentType(MIMEApplicationXML)
	return nil
}

// Links joins the links followed by the property to populate the response's Link HTTP header field.
func (c *DefaultCtx) Links(link ...string) {
	if len(link) == 0 {
		return
	}
	bb := bytebufferpool.Get()
	for i := range link {
		if i%2 == 0 {
			bb.WriteByte('<')
			bb.WriteString(link[i])
			bb.WriteByte('>')
		} else {
			bb.WriteString(`; rel="` + link[i] + `",`)
		}
	}
	c.setCanonical(HeaderLink, strings.TrimRight(c.app.getString(bb.Bytes()), ","))
	bytebufferpool.Put(bb)
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

// Location sets the response Location HTTP header to the specified path parameter.
func (c *DefaultCtx) Location(path string) {
	c.setCanonical(HeaderLocation, path)
}

// Method is an alias of [Request.Method]
func (c *DefaultCtx) Method(override ...string) string {
	return c.Req().Method(override...)
}

// MultipartForm parse form entries from binary.
// This returns a map[string][]string, so given a key the value will be a string slice.
func (c *DefaultCtx) MultipartForm() (*multipart.Form, error) {
	return c.fasthttp.MultipartForm()
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

// ViewBind Add vars to default view var map binding to template engine.
// Variables are read by the Render method and may be overwritten.
func (c *DefaultCtx) ViewBind(vars Map) error {
	// init viewBindMap - lazy map
	for k, v := range vars {
		c.viewBindMap.Store(k, v)
	}
	return nil
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

// Render a template with data and sends a text/html response.
// We support the following engines: https://github.com/gofiber/template
func (c *DefaultCtx) Render(name string, bind Map, layouts ...string) error {
	// Get new buffer from pool
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)

	// Initialize empty bind map if bind is nil
	if bind == nil {
		bind = make(Map)
	}

	// Pass-locals-to-views, bind, appListKeys
	c.renderExtensions(bind)

	var rendered bool
	for i := len(c.app.mountFields.appListKeys) - 1; i >= 0; i-- {
		prefix := c.app.mountFields.appListKeys[i]
		app := c.app.mountFields.appList[prefix]
		if prefix == "" || strings.Contains(c.OriginalURL(), prefix) {
			if len(layouts) == 0 && app.config.ViewsLayout != "" {
				layouts = []string{
					app.config.ViewsLayout,
				}
			}

			// Render template from Views
			if app.config.Views != nil {
				if err := app.config.Views.Render(buf, name, bind, layouts...); err != nil {
					return fmt.Errorf("failed to render: %w", err)
				}

				rendered = true
				break
			}
		}
	}

	if !rendered {
		// Render raw template using 'name' as filepath if no engine is set
		var tmpl *template.Template
		if _, err := readContent(buf, name); err != nil {
			return err
		}
		// Parse template
		tmpl, err := template.New("").Parse(c.app.getString(buf.Bytes()))
		if err != nil {
			return fmt.Errorf("failed to parse: %w", err)
		}
		buf.Reset()
		// Render template
		if err := tmpl.Execute(buf, bind); err != nil {
			return fmt.Errorf("failed to execute: %w", err)
		}
	}

	// Set Content-Type to text/html
	c.fasthttp.Response.Header.SetContentType(MIMETextHTMLCharsetUTF8)
	// Set rendered template to body
	c.fasthttp.Response.SetBody(buf.Bytes())

	return nil
}

func (c *DefaultCtx) renderExtensions(bind any) {
	if bindMap, ok := bind.(Map); ok {
		// Bind view map
		c.viewBindMap.Range(func(key, value any) bool {
			keyValue, ok := key.(string)
			if !ok {
				return true
			}
			if _, ok := bindMap[keyValue]; !ok {
				bindMap[keyValue] = value
			}
			return true
		})

		// Check if the PassLocalsToViews option is enabled (by default it is disabled)
		if c.app.config.PassLocalsToViews {
			// Loop through each local and set it in the map
			c.fasthttp.VisitUserValues(func(key []byte, val any) {
				// check if bindMap doesn't contain the key
				if _, ok := bindMap[c.app.getString(key)]; !ok {
					// Set the key and value in the bindMap
					bindMap[c.app.getString(key)] = val
				}
			})
		}
	}

	if len(c.app.mountFields.appListKeys) == 0 {
		c.app.generateAppListKeys()
	}
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

// Secure returns whether a secure connection was established.
func (c *DefaultCtx) Secure() bool {
	return c.Protocol() == schemeHTTPS
}

// Send sets the HTTP response body without copying it.
// From this point onward the body argument must not be changed.
func (c *DefaultCtx) Send(body []byte) error {
	// Write response body
	c.fasthttp.Response.SetBodyRaw(body)
	return nil
}

var (
	sendFileOnce    sync.Once
	sendFileFS      *fasthttp.FS
	sendFileHandler fasthttp.RequestHandler
)

// SendFile transfers the file from the given path.
// The file is not compressed by default, enable this by passing a 'true' argument
// Sets the Content-Type response HTTP header field based on the filenames extension.
func (c *DefaultCtx) SendFile(file string, compress ...bool) error {
	// Save the filename, we will need it in the error message if the file isn't found
	filename := file

	// https://github.com/valyala/fasthttp/blob/c7576cc10cabfc9c993317a2d3f8355497bea156/fs.go#L129-L134
	sendFileOnce.Do(func() {
		const cacheDuration = 10 * time.Second
		sendFileFS = &fasthttp.FS{
			Root:                 "",
			AllowEmptyRoot:       true,
			GenerateIndexPages:   false,
			AcceptByteRange:      true,
			Compress:             true,
			CompressedFileSuffix: c.app.config.CompressedFileSuffix,
			CacheDuration:        cacheDuration,
			IndexNames:           []string{"index.html"},
			PathNotFound: func(ctx *fasthttp.RequestCtx) {
				ctx.Response.SetStatusCode(StatusNotFound)
			},
		}
		sendFileHandler = sendFileFS.NewRequestHandler()
	})

	// Keep original path for mutable params
	c.req.pathOriginal = utils.CopyString(c.req.pathOriginal)
	// Disable compression
	if len(compress) == 0 || !compress[0] {
		// https://github.com/valyala/fasthttp/blob/7cc6f4c513f9e0d3686142e0a1a5aa2f76b3194a/fs.go#L55
		c.fasthttp.Request.Header.Del(HeaderAcceptEncoding)
	}
	// copy of https://github.com/valyala/fasthttp/blob/7cc6f4c513f9e0d3686142e0a1a5aa2f76b3194a/fs.go#L103-L121 with small adjustments
	if len(file) == 0 || !filepath.IsAbs(file) {
		// extend relative path to absolute path
		hasTrailingSlash := len(file) > 0 && (file[len(file)-1] == '/' || file[len(file)-1] == '\\')

		var err error
		file = filepath.FromSlash(file)
		if file, err = filepath.Abs(file); err != nil {
			return fmt.Errorf("failed to determine abs file path: %w", err)
		}
		if hasTrailingSlash {
			file += "/"
		}
	}
	// convert the path to forward slashes regardless the OS in order to set the URI properly
	// the handler will convert back to OS path separator before opening the file
	file = filepath.ToSlash(file)

	// Restore the original requested URL
	originalURL := utils.CopyString(c.OriginalURL())
	defer c.fasthttp.Request.SetRequestURI(originalURL)
	// Set new URI for fileHandler
	c.fasthttp.Request.SetRequestURI(file)
	// Save status code
	status := c.fasthttp.Response.StatusCode()
	// Serve file
	sendFileHandler(c.fasthttp)
	// Get the status code which is set by fasthttp
	fsStatus := c.fasthttp.Response.StatusCode()
	// Set the status code set by the user if it is different from the fasthttp status code and 200
	if status != fsStatus && status != StatusOK {
		c.Status(status)
	}
	// Check for error
	if status != StatusNotFound && fsStatus == StatusNotFound {
		return NewError(StatusNotFound, fmt.Sprintf("sendfile: file %s not found", filename))
	}
	return nil
}

// SendStatus sets the HTTP status code and if the response body is empty,
// it sets the correct status message in the body.
func (c *DefaultCtx) SendStatus(status int) error {
	c.Status(status)

	// Only set status body when there is no response body
	if len(c.fasthttp.Response.Body()) == 0 {
		return c.SendString(utils.StatusMessage(status))
	}

	return nil
}

// SendString sets the HTTP response body for string types.
// This means no type assertion, recommended for faster performance
func (c *DefaultCtx) SendString(body string) error {
	c.fasthttp.Response.SetBodyString(body)

	return nil
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

// Set sets the response's HTTP header field to the specified key, value.
func (c *DefaultCtx) Set(key, val string) {
	c.fasthttp.Response.Header.Set(key, val)
}

func (c *DefaultCtx) setCanonical(key, val string) {
	c.fasthttp.Response.Header.SetCanonical(utils.UnsafeBytes(key), utils.UnsafeBytes(val))
}

// Subdomains returns a string slice of subdomains in the domain name of the request.
// The subdomain offset, which defaults to 2, is used for determining the beginning of the subdomain segments.
func (c *DefaultCtx) Subdomains(offset ...int) []string {
	o := 2
	if len(offset) > 0 {
		o = offset[0]
	}
	subdomains := strings.Split(c.Host(), ".")
	l := len(subdomains) - o
	// Check index to avoid slice bounds out of range panic
	if l < 0 {
		l = len(subdomains)
	}
	subdomains = subdomains[:l]
	return subdomains
}

// Stale is an alias of [Request.Stale].
func (c *DefaultCtx) Stale() bool {
	return c.req.Stale()
}

// Status sets the HTTP status for the response.
// This method is chainable.
func (c *DefaultCtx) Status(status int) Ctx {
	c.fasthttp.Response.SetStatusCode(status)
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

// Type sets the Content-Type HTTP header to the MIME type specified by the file extension.
func (c *DefaultCtx) Type(extension string, charset ...string) Ctx {
	if len(charset) > 0 {
		c.fasthttp.Response.Header.SetContentType(utils.GetMIME(extension) + "; charset=" + charset[0])
	} else {
		c.fasthttp.Response.Header.SetContentType(utils.GetMIME(extension))
	}
	return c
}

// Vary adds the given header field to the Vary response header.
// This will append the header, if not already listed, otherwise leaves it listed in the current location.
func (c *DefaultCtx) Vary(fields ...string) {
	c.Append(HeaderVary, fields...)
}

// Write appends p into response body.
func (c *DefaultCtx) Write(p []byte) (int, error) {
	c.fasthttp.Response.AppendBody(p)
	return len(p), nil
}

// Writef appends f & a into response body writer.
func (c *DefaultCtx) Writef(f string, a ...any) (int, error) {
	//nolint:wrapcheck // This must not be wrapped
	return fmt.Fprintf(c.fasthttp.Response.BodyWriter(), f, a...)
}

// WriteString appends s to response body.
func (c *DefaultCtx) WriteString(s string) (int, error) {
	c.fasthttp.Response.AppendBodyString(s)
	return len(s), nil
}

// XHR returns a Boolean property, that is true, if the request's X-Requested-With header field is XMLHttpRequest,
// indicating that the request was issued by a client library (such as jQuery).
func (c *DefaultCtx) XHR() bool {
	return utils.EqualFold(c.app.getBytes(c.Get(HeaderXRequestedWith)), []byte("xmlhttprequest"))
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

var localHosts = [...]string{"127.0.0.1", "::1"}

// IsLocalHost will return true if address is a localhost address.
func (*DefaultCtx) isLocalHost(address string) bool {
	for _, h := range localHosts {
		if address == h {
			return true
		}
	}
	return false
}

// IsFromLocal will return true if request came from local.
func (c *DefaultCtx) IsFromLocal() bool {
	return c.isLocalHost(c.fasthttp.RemoteIP().String())
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
