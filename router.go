// ⚡️ Fiber is an Express inspired web framework written in Go with ☕️
// 🤖 Github Repository: https://github.com/gofiber/fiber
// 📌 API Documentation: https://docs.gofiber.io

package fiber

import (
	"log"
	"strings"
	"time"

	fasthttp "github.com/valyala/fasthttp"
)

// Route is a struct that holds all metadata for each registered handler
type Route struct {
	// Booleans for routing
	use  bool // USE matches path prefixes
	star bool // Path equals '*'
	root bool // Path equals '/'

	// Cleaned path data if enabled
	path   string
	params parsedParams

	// Public fields
	Path    string     // Original registered route path
	Method  string     // HTTP method
	Params  []string   // Slice containing the params names
	Handler func(*Ctx) // Ctx handler
}

func (r *Route) match(path, original string) (match bool, values []string) {
	if r.use {
		if r.root || strings.HasPrefix(path, r.path) {
			return true, values
		}
		// Check for a simple path match
	} else if len(r.path) == len(path) && r.path == path {
		return true, values
		// Middleware routes allow prefix matches
	} else if r.root && path == "/" {
		return true, values
	}
	// '*' wildcard matches any path
	if r.star {
		return true, []string{original}
	}
	// Does this route have parameters
	if len(r.Params) > 0 {
		// Match params
		if paramPos, match := r.params.getMatch(path, r.use); match {
			return match, r.params.paramsForPos(original, paramPos)
		}
	}
	// No match
	return false, values
}

func (app *App) next(ctx *Ctx) bool {
	// TODO set unique INT within handler(), not here over and over again
	method := methodINT[ctx.method]
	// Get stack length
	lenr := len(app.stack[method]) - 1
	// Loop over the route stack starting from previous index
	for ctx.index < lenr {
		// Increment stack index
		ctx.index++
		// Get *Route
		route := app.stack[method][ctx.index]
		// Check if it matches the request path
		match, values := route.match(ctx.path, getString(ctx.Fasthttp.URI().Path()))
		// No match, continue
		if !match {
			continue
		}
		// Pass route and param values to Ctx
		ctx.route = route
		ctx.values = values
		// Execute Ctx handler
		route.Handler(ctx)
		// Stop looping the stack
		return true
	}
	return false
}

func (app *App) handler(rctx *fasthttp.RequestCtx) {
	// Acquire Ctx with fasthttp request from pool
	ctx := AcquireCtx(rctx)
	// Attach app poiner to access the routes
	ctx.app = app
	// Attach fasthttp RequestCtx
	ctx.Fasthttp = rctx
	// If CaseSensitive is disabled, we compare everything in lower
	if !app.Settings.CaseSensitive {
		// We are making a copy here to keep access to
		// the original URI
		ctx.path = toLower(getString(rctx.URI().Path()))
	}
	// if StrictRouting is disabled, we strip all trailing slashes
	if !app.Settings.StrictRouting && len(ctx.path) > 1 && ctx.path[len(ctx.path)-1] == '/' {
		ctx.path = trimRight(ctx.path, '/')
	}
	// Find match in stack
	match := app.next(ctx)
	// Send a 404 by default if no route matched
	if !match {
		ctx.SendStatus(404)
	} else if app.Settings.ETag {
		// Generate ETag if enabled and we have a match
		setETag(ctx, false)
	}
	// Release Ctx
	ReleaseCtx(ctx)
}

func (app *App) register(method, path string, handlers ...func(*Ctx)) Router {
	// A route requires atleast one ctx handler
	if len(handlers) == 0 {
		log.Fatalf("Missing handler in route")
	}
	// Cannot have an empty path
	if path == "" {
		path = "/"
	}
	// Path always start with a '/'
	if path[0] != '/' {
		path = "/" + path
	}
	// Create a stripped path in-case sensitive / trailing slashes
	stripped := path
	// Case sensitive routing, all to lowercase
	if !app.Settings.CaseSensitive {
		stripped = toLower(stripped)
	}
	// Strict routing, remove trailing slashes
	if !app.Settings.StrictRouting && len(stripped) > 1 {
		stripped = trimRight(stripped, '/')
	}
	// Is layer a middleware?
	var isUse = method == "USE"
	// Is path a direct wildcard?
	var isStar = path == "/*"
	// Is path a root slash?
	var isRoot = path == "/"
	// Parse path parameters
	var strippedParsed = getParams(stripped)
	var originalParsed = getParams(path)
	// Loop over handlers
	for i := range handlers {
		// Set route metadata
		route := &Route{
			// Router booleans
			use:  isUse,
			star: isStar,
			root: isRoot,
			// Path data
			path:   stripped,
			params: strippedParsed,
			// Public data
			Path:    path,
			Method:  method,
			Params:  originalParsed.params,
			Handler: handlers[i],
		}
		// Middleware route matches all HTTP methods
		if isUse {
			// Add route to all HTTP methods stack
			for m := range methodINT {
				app.addRoute(m, route)
			}
			// Skip to next handler
			continue
		}
		// Add route to stack
		app.addRoute(method, route)
		// Also add GET routes to HEAD stack
		if method == MethodGet {
			app.addRoute(MethodHead, route)
		}
	}
	return app
}

func (app *App) registerStatic(prefix, root string, config ...Static) {
	// Cannot have an empty prefix
	if prefix == "" {
		prefix = "/"
	}
	// Prefix always start with a '/' or '*'
	if prefix[0] != '/' {
		prefix = "/" + prefix
	}
	// Match anything
	var wildcard = false
	if prefix == "*" || prefix == "/*" {
		wildcard = true
		prefix = "/"
	}
	// in case sensitive routing, all to lowercase
	if !app.Settings.CaseSensitive {
		prefix = toLower(prefix)
	}
	// For security we want to restrict to the current work directory.
	if len(root) == 0 {
		root = "."
	}
	// Strip trailing slashes from the root path
	if len(root) > 0 && root[len(root)-1] == '/' {
		root = root[:len(root)-1]
	}
	// isSlash ?
	var isRoot = prefix == "/"
	if strings.Contains(prefix, "*") {
		wildcard = true
		prefix = strings.Split(prefix, "*")[0]
	}
	var stripper = len(prefix)
	if isRoot {
		stripper = 0
	}
	// Fileserver settings
	fs := &fasthttp.FS{
		Root:                 root,
		GenerateIndexPages:   false,
		AcceptByteRange:      false,
		Compress:             false,
		CompressedFileSuffix: ".fiber.gz",
		CacheDuration:        10 * time.Second,
		IndexNames:           []string{"index.html"},
		PathRewrite:          fasthttp.NewPathPrefixStripper(stripper),
		PathNotFound: func(ctx *fasthttp.RequestCtx) {
			ctx.Response.SetStatusCode(404)
		},
	}
	// Set config if provided
	if len(config) > 0 {
		fs.Compress = config[0].Compress
		fs.AcceptByteRange = config[0].ByteRange
		fs.GenerateIndexPages = config[0].Browse
		if config[0].Index != "" {
			fs.IndexNames = []string{config[0].Index}
		}
	}
	fileHandler := fs.NewRequestHandler()
	route := &Route{
		use:    true,
		root:   isRoot,
		Method: "*",
		Path:   prefix,
		Handler: func(c *Ctx) {
			// Do stuff
			if wildcard {
				c.Fasthttp.Request.SetRequestURI(prefix)
			}
			// Serve file
			fileHandler(c.Fasthttp)
			// Return request if found and not forbidden
			status := c.Fasthttp.Response.StatusCode()
			if status != 404 && status != 403 {
				return
			}
			// Reset response to default
			c.Fasthttp.Response.SetStatusCode(200)
			c.Fasthttp.Response.SetBodyString("")
			// Next middleware
			match := c.app.next(c)
			// If no other route is executed return 404 Not Found
			if !match {
				c.Fasthttp.Response.SetStatusCode(404)
				c.Fasthttp.Response.SetBodyString("Not Found")
			}
		},
	}
	// Add route to stack
	app.addRoute(MethodGet, route)
	app.addRoute(MethodHead, route)
}

func (app *App) addRoute(method string, route *Route) {
	// Get unique HTTP method indentifier
	m := methodINT[method]
	// Add route to the stack
	app.stack[m] = append(app.stack[m], route)
}
