package fiber

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/gofiber/utils/v2"
	"github.com/valyala/bytebufferpool"
	"github.com/valyala/fasthttp"
)

var (
	sendFileOnce    sync.Once
	sendFileFS      *fasthttp.FS
	sendFileHandler fasthttp.RequestHandler
)

type Response struct {
	app         *App
	ctx         Ctx
	fasthttp    *fasthttp.Response
	viewBindMap sync.Map // Default view map to bind template engine
}

// ResFmt associates a Content Type to a fiber.Handler for c.Format
type ResFmt struct {
	MediaType string
	Handler   func(Ctx) error
}

func (r *Response) App() *App {
	return r.app
}

// Append the specified value to the HTTP response header field.
// If the header is not already set, it creates the header with the specified value.
func (r *Response) Append(field string, values ...string) {
	if len(values) == 0 {
		return
	}
	h := r.app.getString(r.fasthttp.Header.Peek(field))
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
		r.Set(field, h)
	}
}

func (r *Response) Attachment(filename ...string) {
	if len(filename) > 0 {
		fname := filepath.Base(filename[0])
		r.Type(filepath.Ext(fname))

		r.setCanonical(HeaderContentDisposition, `attachment; filename="`+r.app.quoteString(fname)+`"`)
		return
	}
	r.setCanonical(HeaderContentDisposition, "attachment")
}

// ViewBind adds vars to default view var map binding to template engine.
// Variables are read by the Render method and may be overwritten.
func (r *Response) ViewBind(vars Map) error {
	// init viewBindMap - lazy map
	for k, v := range vars {
		r.viewBindMap.Store(k, v)
	}
	return nil
}

// Cookie sets a cookie by passing a cookie struct.
func (r *Response) Cookie(cookie *Cookie) {
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

	r.fasthttp.Header.SetCookie(fcookie)
	fasthttp.ReleaseCookie(fcookie)
}

// ClearCookie expires a specific cookie by key on the client side.
// If no key is provided it expires all cookies that came with the request.
func (r *Response) ClearCookie(key ...string) {
	if len(key) > 0 {
		for i := range key {
			r.fasthttp.Header.DelClientCookie(key[i])
		}
		return
	}
	r.ctx.Context().Request.Header.VisitAllCookie(func(k, _ []byte) {
		r.fasthttp.Header.DelClientCookieBytes(k)
	})
}

// Download transfers the file from path as an attachment.
// Typically, browsers will prompt the user for download.
// By default, the Content-Disposition header filename= parameter is the filepath (this typically appears in the browser dialog).
// Override this default with the filename parameter.
func (r *Response) Download(file string, filename ...string) error {
	var fname string
	if len(filename) > 0 {
		fname = filename[0]
	} else {
		fname = filepath.Base(file)
	}
	r.setCanonical(HeaderContentDisposition, `attachment; filename="`+r.app.quoteString(fname)+`"`)
	return r.SendFile(file)
}

// Format performs content-negotiation on the Accept HTTP header.
// It uses Accepts to select a proper format and calls the matching
// user-provided handler function.
// If no accepted format is found, and a format with MediaType "default" is given,
// that default handler is called. If no format is found and no default is given,
// StatusNotAcceptable is sent.
func (r *Response) Format(handlers ...ResFmt) error {
	if len(handlers) == 0 {
		return ErrNoHandlers
	}

	r.Vary(HeaderAccept)

	if r.ctx.Get(HeaderAccept) == "" {
		r.fasthttp.Header.SetContentType(handlers[0].MediaType)
		return handlers[0].Handler(r.ctx)
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
	accept := r.ctx.Accepts(types...)

	if accept == "" {
		if defaultHandler == nil {
			return r.SendStatus(StatusNotAcceptable)
		}
		return defaultHandler(r.ctx)
	}

	for _, h := range handlers {
		if h.MediaType == accept {
			r.fasthttp.Header.SetContentType(h.MediaType)
			return h.Handler(r.ctx)
		}
	}

	return fmt.Errorf("%w: format: an Accept was found but no handler was called", errUnreachable)
}

// Get returns the HTTP response header specified by field.
// Field names are case-insensitive.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (r *Response) Get(key string, defaultValue ...string) string {
	return defaultString(r.app.getString(r.fasthttp.Header.Peek(key)), defaultValue)
}

// JSON converts any interface or string to JSON.
// Array and slice values encode as JSON arrays,
// except that []byte encodes as a base64-encoded string,
// and a nil slice encodes as the null JSON value.
// If the ctype parameter is given, this method will set the
// Content-Type header equal to ctype. If ctype is not given,
// The Content-Type header will be set to application/json.
func (r *Response) JSON(data any, ctype ...string) error {
	raw, err := r.app.config.JSONEncoder(data)
	if err != nil {
		return err
	}
	r.fasthttp.SetBodyRaw(raw)
	if len(ctype) > 0 {
		r.fasthttp.Header.SetContentType(ctype[0])
	} else {
		r.fasthttp.Header.SetContentType(MIMEApplicationJSON)
	}
	return nil
}

// JSONP sends a JSON response with JSONP support.
// This method is identical to JSON, except that it opts-in to JSONP callback support.
// By default, the callback name is simply callback.
func (r *Response) JSONP(data any, callback ...string) error {
	raw, err := r.app.config.JSONEncoder(data)
	if err != nil {
		return err
	}

	var result, cb string

	if len(callback) > 0 {
		cb = callback[0]
	} else {
		cb = "callback"
	}

	result = cb + "(" + r.app.getString(raw) + ");"

	r.setCanonical(HeaderXContentTypeOptions, "nosniff")
	r.fasthttp.Header.SetContentType(MIMETextJavaScriptCharsetUTF8)
	return r.SendString(result)
}

// Links joins the links followed by the property to populate the response's Link HTTP header field.
func (r *Response) Links(link ...string) {
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
	r.setCanonical(HeaderLink, strings.TrimRight(r.app.getString(bb.Bytes()), ","))
	bytebufferpool.Put(bb)
}

// Location sets the response Location HTTP header to the specified path parameter.
func (r *Response) Location(path string) {
	r.setCanonical(HeaderLocation, path)
}

// Render a template with data and sends a text/html response.
// We support the following engines: https://github.com/gofiber/template
func (r *Response) Render(name string, bind Map, layouts ...string) error {
	// Get new buffer from pool
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)

	// Initialize empty bind map if bind is nil
	if bind == nil {
		bind = make(Map)
	}

	// Pass-locals-to-views, bind, appListKeys
	r.renderExtensions(bind)

	var rendered bool
	for i := len(r.app.mountFields.appListKeys) - 1; i >= 0; i-- {
		prefix := r.app.mountFields.appListKeys[i]
		app := r.app.mountFields.appList[prefix]
		if prefix == "" || strings.Contains(r.ctx.OriginalURL(), prefix) {
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
		tmpl, err := template.New("").Parse(r.app.getString(buf.Bytes()))
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
	r.fasthttp.Header.SetContentType(MIMETextHTMLCharsetUTF8)
	// Set rendered template to body
	r.fasthttp.SetBody(buf.Bytes())

	return nil
}

func (r *Response) renderExtensions(bind any) {
	if bindMap, ok := bind.(Map); ok {
		// Bind view map
		r.viewBindMap.Range(func(key, value any) bool {
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
		if r.app.config.PassLocalsToViews {
			// Loop through each local and set it in the map
			r.ctx.Context().VisitUserValues(func(key []byte, val any) {
				// check if bindMap doesn't contain the key
				if _, ok := bindMap[r.app.getString(key)]; !ok {
					// Set the key and value in the bindMap
					bindMap[r.app.getString(key)] = val
				}
			})
		}
	}

	if len(r.app.mountFields.appListKeys) == 0 {
		r.app.generateAppListKeys()
	}
}

// Send sets the HTTP response body without copying it.
// From this point onward the body argument must not be changed.
func (r *Response) Send(body []byte) error {
	// Write response body
	r.fasthttp.SetBodyRaw(body)
	return nil
}

// SendFile transfers the file from the given path.
// The file is not compressed by default, enable this by passing a 'true' argument
// Sets the Content-Type response HTTP header field based on the filenames extension.
func (r *Response) SendFile(file string, compress ...bool) error {
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
			CompressedFileSuffix: r.app.config.CompressedFileSuffix,
			CacheDuration:        cacheDuration,
			IndexNames:           []string{"index.html"},
			PathNotFound: func(ctx *fasthttp.RequestCtx) {
				ctx.Response.SetStatusCode(StatusNotFound)
			},
		}
		sendFileHandler = sendFileFS.NewRequestHandler()
	})

	// Keep original path for mutable params
	r.ctx.Req().pathOriginal = utils.CopyString(r.ctx.Req().pathOriginal)
	// Disable compression
	if len(compress) == 0 || !compress[0] {
		// https://github.com/valyala/fasthttp/blob/7cc6f4c513f9e0d3686142e0a1a5aa2f76b3194a/fs.go#L55
		r.ctx.Context().Request.Header.Del(HeaderAcceptEncoding)
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
	originalURL := utils.CopyString(r.ctx.OriginalURL())
	defer r.ctx.Context().Request.SetRequestURI(originalURL)
	// Set new URI for fileHandler
	r.ctx.Context().Request.SetRequestURI(file)
	// Save status code
	status := r.fasthttp.StatusCode()
	// Serve file
	sendFileHandler(r.ctx.Context())
	// Get the status code which is set by fasthttp
	fsStatus := r.fasthttp.StatusCode()
	// Set the status code set by the user if it is different from the fasthttp status code and 200
	if status != fsStatus && status != StatusOK {
		r.Status(status)
	}
	// Check for error
	if status != StatusNotFound && fsStatus == StatusNotFound {
		return NewError(StatusNotFound, fmt.Sprintf("sendfile: file %s not found", filename))
	}
	return nil
}

// SendStatus sets the HTTP status code and if the response body is empty,
// it sets the correct status message in the body.
func (r *Response) SendStatus(status int) error {
	r.Status(status)

	// Only set status body when there is no response body
	if len(r.fasthttp.Body()) == 0 {
		return r.SendString(utils.StatusMessage(status))
	}

	return nil
}

// SendString sets the HTTP response body for string types.
// This means no type assertion, recommended for faster performance
func (r *Response) SendString(body string) error {
	r.fasthttp.SetBodyString(body)
	return nil
}

// Set sets the response's HTTP header field to the specified key, value.
func (r *Response) Set(key, val string) {
	r.fasthttp.Header.Set(key, val)
}

// setCanonical is the same as set, but it assumes key is already in canonical form,
// making it more efficient.
func (r *Response) setCanonical(key, val string) {
	r.fasthttp.Header.SetCanonical(utils.UnsafeBytes(key), utils.UnsafeBytes(val))
}

// Status sets the HTTP status for the response.
// This method is chainable.
func (r *Response) Status(status int) *Response {
	r.fasthttp.SetStatusCode(status)
	return r
}

// Type sets the Content-Type HTTP header to the MIME type specified by the file extension.
func (r *Response) Type(extension string, charset ...string) *Response {
	if len(charset) > 0 {
		r.fasthttp.Header.SetContentType(utils.GetMIME(extension) + "; charset=" + charset[0])
	} else {
		r.fasthttp.Header.SetContentType(utils.GetMIME(extension))
	}
	return r
}

// Vary adds the given header field to the Vary response header.
// This will append the header, if not already listed, otherwise leaves it listed in the current location.
func (r *Response) Vary(fields ...string) {
	r.Append(HeaderVary, fields...)
}

// Write appends p into response body.
func (r *Response) Write(p []byte) (int, error) {
	r.fasthttp.AppendBody(p)
	return len(p), nil
}

// Writef appends f & a into response body writer.
func (r *Response) Writef(f string, a ...any) (int, error) {
	//nolint:wrapcheck // This must not be wrapped
	return fmt.Fprintf(r.fasthttp.BodyWriter(), f, a...)
}

// WriteString appends s to response body.
func (r *Response) WriteString(s string) (int, error) {
	r.fasthttp.AppendBodyString(s)
	return len(s), nil
}

// XML converts any interface or string to XML.
// This method also sets the content header to application/xml.
func (r *Response) XML(data any) error {
	raw, err := r.app.config.XMLEncoder(data)
	if err != nil {
		return err
	}
	r.fasthttp.SetBodyRaw(raw)
	r.fasthttp.Header.SetContentType(MIMEApplicationXML)
	return nil
}
