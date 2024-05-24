package fiber

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gofiber/utils/v2"
	"github.com/valyala/fasthttp"
)

type Request struct {
	app                 *App              // Reference to the parent App.
	ctx                 Ctx               // Reference to the parent Ctx.
	fasthttp            *fasthttp.Request // Reference to the underlying fasthttp.Request object.
	route               *Route            // Reference to *Route
	path                string            // HTTP path with the modifications by the configuration -> string copy from pathBuffer
	pathBuffer          []byte            // HTTP path buffer
	detectionPath       string            // Route detection path                                  -> string copy from detectionPathBuffer
	detectionPathBuffer []byte            // HTTP detectionPath buffer
	treePath            string            // Path for the search in the tree
	pathOriginal        string            // Original HTTP path
	values              [maxParams]string // Route parameter values
	baseURI             string            // Memoized base HTTP URI of the current request.
	method              string            // HTTP method
	methodINT           int               // HTTP method INT equivalent
}

// Accepts checks if the specified extensions or content types are acceptable.
func (r *Request) Accepts(offers ...string) string {
	return getOffer(r.fasthttp.Header.Peek(HeaderAccept), acceptsOfferType, offers...)
}

// AcceptsCharsets checks if the specified charset is acceptable.
func (r *Request) AcceptsCharsets(offers ...string) string {
	return getOffer(r.fasthttp.Header.Peek(HeaderAcceptCharset), acceptsOffer, offers...)
}

// AcceptsEncodings checks if the specified encoding is acceptable.
func (r *Request) AcceptsEncodings(offers ...string) string {
	return getOffer(r.fasthttp.Header.Peek(HeaderAcceptEncoding), acceptsOffer, offers...)
}

// AcceptsLanguages checks if the specified language is acceptable.
func (r *Request) AcceptsLanguages(offers ...string) string {
	return getOffer(r.fasthttp.Header.Peek(HeaderAcceptLanguage), acceptsOffer, offers...)
}

func (r *Request) App() *App {
	return r.app
}

// Method returns the HTTP request method for the context, optionally overridden by the provided argument.
// If no override is given or if the provided override is not a valid HTTP method, it returns the current method from the context.
// Otherwise, it updates the context's method and returns the overridden method as a string.
func (r *Request) Method(override ...string) string {
	if len(override) == 0 {
		// Nothing to override, just return current method from context
		return r.method
	}

	method := utils.ToUpper(override[0])
	mINT := r.app.methodInt(method)
	if mINT == -1 {
		// Provided override does not valid HTTP method, no override, return current method
		return r.method
	}

	r.method = method
	r.methodINT = mINT
	return r.method
}

// OriginalURL contains the original request URL.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (r *Request) OriginalURL() string {
	return r.app.getString(r.fasthttp.Header.RequestURI())
}

// BaseURL returns (protocol + host + base path).
func (r *Request) BaseURL() string {
	// TODO: Could be improved: 53.8 ns/op  32 B/op  1 allocs/op
	// Should work like https://codeigniter.com/user_guide/helpers/url_helper.html
	if r.baseURI != "" {
		return r.baseURI
	}
	r.baseURI = r.Scheme() + "://" + r.Host()
	return r.baseURI
}

// Path returns the path part of the request URL.
// Optionally, you could override the path.
func (r *Request) Path(override ...string) string {
	if len(override) != 0 && r.path != override[0] {
		// Set new path to context
		r.pathOriginal = override[0]

		// Set new path to request context
		r.fasthttp.URI().SetPath(r.pathOriginal)
		// Prettify path
		r.configDependentPaths()
	}
	return r.path
}

// configDependentPaths set paths for route recognition and prepared paths for the user,
// here the features for caseSensitive, decoded paths, strict paths are evaluated
func (r *Request) configDependentPaths() {
	r.pathBuffer = append(r.pathBuffer[0:0], r.pathOriginal...)
	// If UnescapePath enabled, we decode the path and save it for the framework user
	if r.app.config.UnescapePath {
		r.pathBuffer = fasthttp.AppendUnquotedArg(r.pathBuffer[:0], r.pathBuffer)
	}
	r.path = r.app.getString(r.pathBuffer)

	// another path is specified which is for routing recognition only
	// use the path that was changed by the previous configuration flags
	r.detectionPathBuffer = append(r.detectionPathBuffer[0:0], r.pathBuffer...)
	// If CaseSensitive is disabled, we lowercase the original path
	if !r.app.config.CaseSensitive {
		r.detectionPathBuffer = utils.ToLowerBytes(r.detectionPathBuffer)
	}
	// If StrictRouting is disabled, we strip all trailing slashes
	if !r.app.config.StrictRouting && len(r.detectionPathBuffer) > 1 && r.detectionPathBuffer[len(r.detectionPathBuffer)-1] == '/' {
		r.detectionPathBuffer = bytes.TrimRight(r.detectionPathBuffer, "/")
	}
	r.detectionPath = r.app.getString(r.detectionPathBuffer)

	// Define the path for dividing routes into areas for fast tree detection, so that fewer routes need to be traversed,
	// since the first three characters area select a list of routes
	r.treePath = r.treePath[0:0]
	const maxDetectionPaths = 3
	if len(r.detectionPath) >= maxDetectionPaths {
		r.treePath = r.detectionPath[:maxDetectionPaths]
	}
}

// Protocol returns the HTTP protocol of request: HTTP/1.1 and HTTP/2.
func (r *Request) Protocol() string {
	return r.app.getString(r.fasthttp.Header.Protocol())
}

// Scheme contains the request protocol string: http or https for TLS requests.
// Please use Config.EnableTrustedProxyCheck to prevent header spoofing, in case when your app is behind the proxy.
func (r *Request) Scheme() string {
	if string(r.fasthttp.URI().Scheme()) == "https" {
		return schemeHTTPS
	}
	if !r.ctx.IsProxyTrusted() {
		return schemeHTTP
	}

	scheme := schemeHTTP
	const lenXHeaderName = 12
	r.fasthttp.Header.VisitAll(func(key, val []byte) {
		if len(key) < lenXHeaderName {
			return // Neither "X-Forwarded-" nor "X-Url-Scheme"
		}
		switch {
		case bytes.HasPrefix(key, []byte("X-Forwarded-")):
			if string(key) == HeaderXForwardedProto ||
				string(key) == HeaderXForwardedProtocol {
				v := r.app.getString(val)
				commaPos := strings.IndexByte(v, ',')
				if commaPos != -1 {
					scheme = v[:commaPos]
				} else {
					scheme = v
				}
			} else if string(key) == HeaderXForwardedSsl && string(val) == "on" {
				scheme = schemeHTTPS
			}

		case string(key) == HeaderXUrlScheme:
			scheme = r.app.getString(val)
		}
	})
	return scheme
}

// Host contains the host derived from the X-Forwarded-Host or Host HTTP header.
// Returned value is only valid within the handler. Do not store any references.
// In a network context, `Host` refers to the combination of a hostname and potentially a port number used for connecting,
// while `Hostname` refers specifically to the name assigned to a device on a network, excluding any port information.
// Example: URL: https://example.com:8080 -> Host: example.com:8080
// Make copies or use the Immutable setting instead.
// Please use Config.EnableTrustedProxyCheck to prevent header spoofing, in case when your app is behind the proxy.
func (r *Request) Host() string {
	if r.ctx.IsProxyTrusted() {
		if host := r.Get(HeaderXForwardedHost); len(host) > 0 {
			commaPos := strings.Index(host, ",")
			if commaPos != -1 {
				return host[:commaPos]
			}
			return host
		}
	}
	return r.app.getString(r.fasthttp.URI().Host())
}

// Hostname contains the hostname derived from the X-Forwarded-Host or Host HTTP header using the r.Host() method.
// Returned value is only valid within the handler. Do not store any references.
// Example: URL: https://example.com:8080 -> Hostname: example.com
// Make copies or use the Immutable setting instead.
// Please use Config.EnableTrustedProxyCheck to prevent header spoofing, in case when your app is behind the proxy.
func (r *Request) Hostname() string {
	addr, _ := parseAddr(r.Host())

	return addr
}

// Port returns the remote port of the request.
func (r *Request) Port() string {
	tcpaddr, ok := r.ctx.Context().RemoteAddr().(*net.TCPAddr)
	if !ok {
		panic(errors.New("failed to type-assert to *net.TCPAddr"))
	}
	return strconv.Itoa(tcpaddr.Port)
}

// IP returns the remote IP address of the request.
// If ProxyHeader and IP Validation is configured, it will parse that header and return the first valid IP address.
// Please use Config.EnableTrustedProxyCheck to prevent header spoofing, in case when your app is behind the proxy.
func (r *Request) IP() string {
	if r.ctx.IsProxyTrusted() && len(r.app.config.ProxyHeader) > 0 {
		return r.extractIPFromHeader(r.app.config.ProxyHeader)
	}

	return r.ctx.Context().RemoteIP().String()
}

// extractIPFromHeader will attempt to pull the real client IP from the given header when IP validation is enabled.
// currently, it will return the first valid IP address in header.
// when IP validation is disabled, it will simply return the value of the header without any inspection.
// Implementation is almost the same as in extractIPsFromHeader, but without allocation of []string.
func (r *Request) extractIPFromHeader(header string) string {
	if r.app.config.EnableIPValidation {
		headerValue := r.Get(header)

		i := 0
		j := -1

	iploop:
		for {
			var v4, v6 bool

			// Manually splitting string without allocating slice, working with parts directly
			i, j = j+1, j+2

			if j > len(headerValue) {
				break
			}

			for j < len(headerValue) && headerValue[j] != ',' {
				if headerValue[j] == ':' {
					v6 = true
				} else if headerValue[j] == '.' {
					v4 = true
				}
				j++
			}

			for i < j && headerValue[i] == ' ' {
				i++
			}

			s := strings.TrimRight(headerValue[i:j], " ")

			if r.app.config.EnableIPValidation {
				if (!v6 && !v4) || (v6 && !utils.IsIPv6(s)) || (v4 && !utils.IsIPv4(s)) {
					continue iploop
				}
			}

			return s
		}

		return r.ctx.Context().RemoteIP().String()
	}

	// default behavior if IP validation is not enabled is just to return whatever value is
	// in the proxy header. Even if it is empty or invalid
	return r.Get(r.app.config.ProxyHeader)
}

// IPs returns a string slice of IP addresses specified in the X-Forwarded-For request header.
// When IP validation is enabled, only valid IPs are returned.
func (r *Request) IPs() []string {
	return r.extractIPsFromHeader(HeaderXForwardedFor)
}

// extractIPsFromHeader will return a slice of IPs it found given a header name in the order they appear.
// When IP validation is enabled, any invalid IPs will be omitted.
func (r *Request) extractIPsFromHeader(header string) []string {
	// TODO: Reuse the c.extractIPFromHeader func somehow in here

	headerValue := r.Get(header)

	// We can't know how many IPs we will return, but we will try to guess with this constant division.
	// Counting ',' makes function slower for about 50ns in general case.
	const maxEstimatedCount = 8
	estimatedCount := len(headerValue) / maxEstimatedCount
	if estimatedCount > maxEstimatedCount {
		estimatedCount = maxEstimatedCount // Avoid big allocation on big header
	}

	ipsFound := make([]string, 0, estimatedCount)

	i := 0
	j := -1

iploop:
	for {
		var v4, v6 bool

		// Manually splitting string without allocating slice, working with parts directly
		i, j = j+1, j+2

		if j > len(headerValue) {
			break
		}

		for j < len(headerValue) && headerValue[j] != ',' {
			if headerValue[j] == ':' {
				v6 = true
			} else if headerValue[j] == '.' {
				v4 = true
			}
			j++
		}

		for i < j && (headerValue[i] == ' ' || headerValue[i] == ',') {
			i++
		}

		s := strings.TrimRight(headerValue[i:j], " ")

		if r.app.config.EnableIPValidation {
			// Skip validation if IP is clearly not IPv4/IPv6, otherwise validate without allocations
			if (!v6 && !v4) || (v6 && !utils.IsIPv6(s)) || (v4 && !utils.IsIPv4(s)) {
				continue iploop
			}
		}

		ipsFound = append(ipsFound, s)
	}

	return ipsFound
}

// Is returns the matching content type,
// if the incoming request's Content-Type HTTP header field matches the MIME type specified by the type parameter
func (r *Request) Is(extension string) bool {
	extensionHeader := utils.GetMIME(extension)
	if extensionHeader == "" {
		return false
	}

	return strings.HasPrefix(
		strings.TrimLeft(utils.UnsafeString(r.fasthttp.Header.ContentType()), " "),
		extensionHeader,
	)
}

var localHosts = [...]string{"127.0.0.1", "::1"}

// IsLocalHost will return true if address is a localhost address.
func isLocalHost(address string) bool {
	for _, h := range localHosts {
		if address == h {
			return true
		}
	}
	return false
}

// IsFromLocal will return true if request came from local.
func (r *Request) IsFromLocal() bool {
	return isLocalHost(r.ctx.Context().RemoteIP().String())
}

// BodyRaw contains the raw body submitted in a POST request.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (r *Request) BodyRaw() []byte {
	if r.app.config.Immutable {
		return utils.CopyBytes(r.fasthttp.Body())
	}
	return r.fasthttp.Body()
}

// Body contains the raw body submitted in a POST request.
// This method will decompress the body if the 'Content-Encoding' header is provided.
// It returns the original (or decompressed) body data which is valid only within the handler.
// Don't store direct references to the returned data.
// If you need to keep the body's data later, make a copy or use the Immutable option.
func (r *Request) Body() []byte {
	var (
		err                error
		body, originalBody []byte
		headerEncoding     string
		encodingOrder      = []string{"", "", ""}
	)

	// faster than peek
	r.fasthttp.Header.VisitAll(func(key, value []byte) {
		if r.app.getString(key) == HeaderContentEncoding {
			headerEncoding = r.app.getString(value)
		}
	})

	// Split and get the encodings list, in order to attend the
	// rule defined at: https://www.rfc-editor.org/rfc/rfc9110#section-8.4-5
	encodingOrder = getSplicedStrList(headerEncoding, encodingOrder)
	if len(encodingOrder) == 0 {
		if r.app.config.Immutable {
			return utils.CopyBytes(r.fasthttp.Body())
		}
		return r.fasthttp.Body()
	}

	var decodesRealized uint8
	body, decodesRealized, err = r.tryDecodeBodyInOrder(&originalBody, encodingOrder)

	// Ensure that the body will be the original
	if originalBody != nil && decodesRealized > 0 {
		r.fasthttp.SetBodyRaw(originalBody)
	}
	if err != nil {
		return []byte(err.Error())
	}

	if r.app.config.Immutable {
		return utils.CopyBytes(body)
	}
	return body
}

func (r *Request) tryDecodeBodyInOrder(
	originalBody *[]byte,
	encodings []string,
) ([]byte, uint8, error) {
	var (
		err             error
		body            []byte
		decodesRealized uint8
	)

	for index, encoding := range encodings {
		decodesRealized++
		switch encoding {
		case StrGzip:
			body, err = r.fasthttp.BodyGunzip()
		case StrBr, StrBrotli:
			body, err = r.fasthttp.BodyUnbrotli()
		case StrDeflate:
			body, err = r.fasthttp.BodyInflate()
		default:
			decodesRealized--
			if len(encodings) == 1 {
				body = r.fasthttp.Body()
			}
			return body, decodesRealized, nil
		}

		if err != nil {
			return nil, decodesRealized, err
		}

		// Only execute body raw update if it has a next iteration to try to decode
		if index < len(encodings)-1 && decodesRealized > 0 {
			if index == 0 {
				tempBody := r.fasthttp.Body()
				*originalBody = make([]byte, len(tempBody))
				copy(*originalBody, tempBody)
			}
			r.fasthttp.SetBodyRaw(body)
		}
	}

	return body, decodesRealized, nil
}

// Get returns the HTTP request header specified by field.
// Field names are case-insensitive
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (r *Request) Get(key string, defaultValue ...string) string {
	return defaultString(r.app.getString(r.fasthttp.Header.Peek(key)), defaultValue)
}

// Cookies are used for getting a cookie value by key.
// Defaults to the empty string "" if the cookie doesn't exist.
// If a default value is given, it will return that value if the cookie doesn't exist.
// The returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (r *Request) Cookies(key string, defaultValue ...string) string {
	return defaultString(r.app.getString(r.fasthttp.Header.Cookie(key)), defaultValue)
}

// Fresh returns true when the response is still “fresh” in the client's cache,
// otherwise false is returned to indicate that the client cache is now stale
// and the full response should be sent.
// When a client sends the Cache-Control: no-cache request header to indicate an end-to-end
// reload request, this module will return false to make handling these requests transparent.
// https://github.com/jshttp/fresh/blob/10e0471669dbbfbfd8de65bc6efac2ddd0bfa057/index.js#L33
func (r *Request) Fresh() bool {
	// fields
	modifiedSince := r.Get(HeaderIfModifiedSince)
	noneMatch := r.Get(HeaderIfNoneMatch)

	// unconditional request
	if modifiedSince == "" && noneMatch == "" {
		return false
	}

	// Always return stale when Cache-Control: no-cache
	// to support end-to-end reload requests
	// https://tools.ietf.org/html/rfc2616#section-14.9.4
	cacheControl := r.Get(HeaderCacheControl)
	if cacheControl != "" && isNoCache(cacheControl) {
		return false
	}

	// if-none-match
	if noneMatch != "" && noneMatch != "*" {
		etag := r.ctx.Res().Get(HeaderETag)
		if etag == "" {
			return false
		}
		if r.app.isEtagStale(etag, r.app.getBytes(noneMatch)) {
			return false
		}

		if modifiedSince != "" {
			lastModified := r.ctx.Res().Get(HeaderLastModified)
			if lastModified != "" {
				lastModifiedTime, err := http.ParseTime(lastModified)
				if err != nil {
					return false
				}
				modifiedSinceTime, err := http.ParseTime(modifiedSince)
				if err != nil {
					return false
				}
				return lastModifiedTime.Before(modifiedSinceTime)
			}
		}
	}
	return true
}

// Secure returns whether a secure connection was established.
func (r *Request) Secure() bool {
	return r.Protocol() == schemeHTTPS
}

// Stale is the opposite of [Request.Fresh] and returns true when the response
// to this request is no longer "fresh" in the client's cache.
func (r *Request) Stale() bool {
	return !r.Fresh()
}

// Subdomains returns a string slice of subdomains in the domain name of the request.
// The subdomain offset, which defaults to 2, is used for determining the beginning of the subdomain segments.
func (r *Request) Subdomains(offset ...int) []string {
	o := 2
	if len(offset) > 0 {
		o = offset[0]
	}
	subdomains := strings.Split(r.Host(), ".")
	l := len(subdomains) - o
	// Check index to avoid slice bounds out of range panic
	if l < 0 {
		l = len(subdomains)
	}
	subdomains = subdomains[:l]
	return subdomains
}

// XHR returns a Boolean property, that is true, if the request's X-Requested-With header field is XMLHttpRequest,
// indicating that the request was issued by a client library (such as jQuery).
func (r *Request) XHR() bool {
	return utils.EqualFold(r.fasthttp.Header.Peek(HeaderXRequestedWith), []byte("xmlhttprequest"))
}

// MultipartForm parse form entries from binary.
// This returns a map[string][]string, so given a key the value will be a string slice.
func (r *Request) MultipartForm() (*multipart.Form, error) {
	return r.fasthttp.MultipartForm()
}

// Params is used to get the route parameters.
// Defaults to empty string "" if the param doesn't exist.
// If a default value is given, it will return that value if the param doesn't exist.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (r *Request) Params(key string, defaultValue ...string) string {
	if key == "*" || key == "+" {
		key += "1"
	}
	for i := range r.route.Params {
		if len(key) != len(r.route.Params[i]) {
			continue
		}
		if r.route.Params[i] == key || (!r.app.config.CaseSensitive && utils.EqualFold(r.route.Params[i], key)) {
			// in case values are not here
			if len(r.values) <= i || len(r.values[i]) == 0 {
				break
			}
			return r.values[i]
		}
	}
	return defaultString("", defaultValue)
}

// Query returns the query string parameter in the url.
// Defaults to empty string "" if the query doesn't exist.
// If a default value is given, it will return that value if the query doesn't exist.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (r *Request) Query(key string, defaultValue ...string) string {
	query := r.app.getString(r.fasthttp.URI().QueryArgs().Peek(key))
	return defaultString(query, defaultValue)
}

// Queries returns a map of query parameters and their values.
//
// GET /?name=alex&wanna_cake=2&id=
// Queries()["name"] == "alex"
// Queries()["wanna_cake"] == "2"
// Queries()["id"] == ""
//
// GET /?field1=value1&field1=value2&field2=value3
// Queries()["field1"] == "value2"
// Queries()["field2"] == "value3"
//
// GET /?list_a=1&list_a=2&list_a=3&list_b[]=1&list_b[]=2&list_b[]=3&list_c=1,2,3
// Queries()["list_a"] == "3"
// Queries()["list_b[]"] == "3"
// Queries()["list_c"] == "1,2,3"
//
// GET /api/search?filters.author.name=John&filters.category.name=Technology&filters[customer][name]=Alice&filters[status]=pending
// Queries()["filters.author.name"] == "John"
// Queries()["filters.category.name"] == "Technology"
// Queries()["filters[customer][name]"] == "Alice"
// Queries()["filters[status]"] == "pending"
func (r *Request) Queries() map[string]string {
	m := make(map[string]string, r.fasthttp.URI().QueryArgs().Len())
	r.fasthttp.URI().QueryArgs().VisitAll(func(key, value []byte) {
		m[r.app.getString(key)] = r.app.getString(value)
	})
	return m
}

// Range returns a struct containing the type and a slice of ranges.
func (r *Request) Range(size int) (Range, error) {
	var (
		rangeData Range
		ranges    string
	)
	rangeStr := r.Get(HeaderRange)

	i := strings.IndexByte(rangeStr, '=')
	if i == -1 || strings.Contains(rangeStr[i+1:], "=") {
		return rangeData, ErrRangeMalformed
	}
	rangeData.Type = rangeStr[:i]
	ranges = rangeStr[i+1:]

	var (
		singleRange string
		moreRanges  = ranges
	)
	for moreRanges != "" {
		singleRange = moreRanges
		if i := strings.IndexByte(moreRanges, ','); i >= 0 {
			singleRange = moreRanges[:i]
			moreRanges = moreRanges[i+1:]
		} else {
			moreRanges = ""
		}

		var (
			startStr, endStr string
			i                int
		)
		if i = strings.IndexByte(singleRange, '-'); i == -1 {
			return rangeData, ErrRangeMalformed
		}
		startStr = singleRange[:i]
		endStr = singleRange[i+1:]

		start, startErr := fasthttp.ParseUint(utils.UnsafeBytes(startStr))
		end, endErr := fasthttp.ParseUint(utils.UnsafeBytes(endStr))
		if startErr != nil { // -nnn
			start = size - end
			end = size - 1
		} else if endErr != nil { // nnn-
			end = size - 1
		}
		if end > size-1 { // limit last-byte-pos to current length
			end = size - 1
		}
		if start > end || start < 0 {
			continue
		}
		rangeData.Ranges = append(rangeData.Ranges, struct {
			Start int
			End   int
		}{
			start,
			end,
		})
	}
	if len(rangeData.Ranges) < 1 {
		return rangeData, ErrRangeUnsatisfiable
	}

	return rangeData, nil
}

// Route returns the matched Route struct.
func (r *Request) Route() *Route {
	if r.route == nil {
		// Fallback for fasthttp error handler
		return &Route{
			path:     r.pathOriginal,
			Path:     r.pathOriginal,
			Method:   r.method,
			Handlers: make([]Handler, 0),
			Params:   make([]string, 0),
		}
	}
	return r.route
}
