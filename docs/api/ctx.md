---
id: ctx
title: 🧠 Ctx
description: >-
  The Ctx interface represents the Context which hold the HTTP request and
  response. It has methods for the request query string, parameters, body, HTTP
  headers, and so on.
sidebar_position: 3
---

The Ctx interface represents the Context which hold the HTTP request and
response. It has methods for the request query string, parameters, body, HTTP
headers, and so on. The Ctx API is split between methods acting on the
incoming [`Request`](#request) and the outgoing [`Response`](#response).

:::tip
Ctx provides aliases for many `Request` and `Response` methods. For example, `c.Res().Send()` is the same as `c.Send()`. Examples on this page will show usage both ways.
:::

## Req

Req returns the fiber [`Request`](#request) object, which contains accessors and
methods to interact with the incoming HTTP request data.

```go title="Signature"
func (c Ctx) Req() *Request
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Req().Method()
  // => "GET"
  return nil
})
```

## Res

Res returns the fiber [`Response`](#response) object, which contains methods to set and
modify the outgoing HTTP response data.

```go title="Signature"
func (c Ctx) Res() *Response
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Res().WriteString("Hello, World!")
  // => "Hello, World!"
  return nil
})
```

## App

Returns the [\*App](ctx.md) reference so you can easily access all application settings.

```go title="Signature"
func (c Ctx) App() *App
```

```go title="Example"
app.Get("/stack", func(c fiber.Ctx) error {
  return c.JSON(c.App().Stack())
})
```

## Bind

Bind is a method that support supports bindings for the request/response body, query parameters, URL parameters, cookies and much more.
It returns a pointer to the [Bind](./bind.md) struct which contains all the methods to bind the request/response data.

For detailed information check the [Bind](./bind.md) documentation.

```go title="Signature"
func (c Ctx) Bind() *Bind
```

```go title="Example"
app.Post("/", func(c fiber.Ctx) error {
  user := new(User)
  // Bind the request body to a struct:
  return c.Bind().Body(user)
})
```

## Context

Returns [\*fasthttp.RequestCtx](https://godoc.org/github.com/valyala/fasthttp#RequestCtx) that is compatible with the context.Context interface that requires a deadline, a cancellation signal, and other values across API boundaries.

```go title="Signature"
func (c Ctx) Context() *fasthttp.RequestCtx
```

:::info
Please read the [Fasthttp Documentation](https://pkg.go.dev/github.com/valyala/fasthttp?tab=doc) for more information.
:::

## ClientHelloInfo

ClientHelloInfo contains information from a ClientHello message in order to guide application logic in the GetCertificate and GetConfigForClient callbacks.
You can refer to the [ClientHelloInfo](https://golang.org/pkg/crypto/tls/#ClientHelloInfo) struct documentation for more information on the returned struct.

```go title="Signature"
func (c Ctx) ClientHelloInfo() *tls.ClientHelloInfo
```

```go title="Example"
// GET http://example.com/hello
app.Get("/hello", func(c fiber.Ctx) error {
  chi := c.ClientHelloInfo()
  // ...
})
```

## FormFile

MultipartForm files can be retrieved by name, the **first** file from the given key is returned.

```go title="Signature"
func (c Ctx) FormFile(key string) (*multipart.FileHeader, error)
```

```go title="Example"
app.Post("/", func(c fiber.Ctx) error {
  // Get first file from form field "document":
  file, err := c.FormFile("document")

  // Save file to root directory:
  return c.SaveFile(file, fmt.Sprintf("./%s", file.Filename))
})
```

## FormValue

Any form values can be retrieved by name, the **first** value from the given key is returned.

```go title="Signature"
func (c Ctx) FormValue(key string, defaultValue ...string) string
```

```go title="Example"
app.Post("/", func(c fiber.Ctx) error {
  // Get first value from form field "name":
  c.FormValue("name")
  // => "john" or "" if not exist

  // ..
})
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::

## GetReqHeaders

Returns the HTTP request headers as a map. Since a header can be set multiple times in a single request, the values of the map are slices of strings containing all the different values of the header.

```go title="Signature"
func (c Ctx) GetReqHeaders() map[string][]string
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::

## GetRespHeader

Returns the HTTP response header specified by the field.

:::tip
The match is **case-insensitive**.
:::

```go title="Signature"
func (c Ctx) GetRespHeader(key string, defaultValue ...string) string
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.GetRespHeader("X-Request-Id")       // "8d7ad5e3-aaf3-450b-a241-2beb887efd54"
  c.GetRespHeader("Content-Type")       // "text/plain"
  c.GetRespHeader("something", "john")  // "john"
  // ..
})
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::

## GetRespHeaders

Returns the HTTP response headers as a map. Since a header can be set multiple times in a single request, the values of the map are slices of strings containing all the different values of the header.

```go title="Signature"
func (c Ctx) GetRespHeaders() map[string][]string
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::

## GetRouteURL

Generates URLs to named routes, with parameters. URLs are relative, for example: "/user/1831"

```go title="Signature"
func (c Ctx) GetRouteURL(routeName string, params Map) (string, error)
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
    return c.SendString("Home page")
}).Name("home")

app.Get("/user/:id", func(c fiber.Ctx) error {
    return c.SendString(c.Params("id"))
}).Name("user.show")

app.Get("/test", func(c fiber.Ctx) error {
    location, _ := c.GetRouteURL("user.show", fiber.Map{"id": 1})
    return c.SendString(location)
})

// /test returns "/user/1"
```

## IsFromLocal

Returns true if request came from localhost

```go title="Signature"
func (c Ctx) IsFromLocal() bool {
```

```go title="Example"

app.Get("/", func(c fiber.Ctx) error {
  // If request came from localhost, return true else return false
  c.IsFromLocal()

  // ...
})
```

## IsProxyTrusted

Checks trustworthiness of remote ip.
If [`EnableTrustedProxyCheck`](fiber.md#enabletrustedproxycheck) false, it returns true
IsProxyTrusted can check remote ip by proxy ranges and ip map.

```go title="Signature"
func (c Ctx) IsProxyTrusted() bool
```

```go title="Example"

app := fiber.New(fiber.Config{
  // EnableTrustedProxyCheck enables the trusted proxy check
  EnableTrustedProxyCheck: true,
  // TrustedProxies is a list of trusted proxy IP addresses
  TrustedProxies: []string{"0.8.0.0", "0.8.0.1"},
})
        

app.Get("/", func(c fiber.Ctx) error {
  // If request came from trusted proxy, return true else return false
  c.IsProxyTrusted()

  // ...
})

```

## Locals

A method that stores variables scoped to the request and, therefore, are available only to the routes that match the request.

:::tip
This is useful if you want to pass some **specific** data to the next middleware.
:::

```go title="Signature"
func (c Ctx) Locals(key any, value ...any) any
```

```go title="Example"

// key is an unexported type for keys defined in this package.
// This prevents collisions with keys defined in other packages.
type key int

// userKey is the key for user.User values in Contexts. It is
// unexported; clients use user.NewContext and user.FromContext
// instead of using this key directly.
var userKey key

app.Use(func(c fiber.Ctx) error {
  c.Locals(userKey, "admin")
  return c.Next()
})

app.Get("/admin", func(c fiber.Ctx) error {
  if c.Locals(userKey) == "admin" {
    return c.Status(fiber.StatusOK).SendString("Welcome, admin!")
  }
  return c.SendStatus(fiber.StatusForbidden)

})
```

An alternative version of the Locals method that takes advantage of Go's generics feature is also available. This version 
allows for the manipulation and retrieval of local values within a request's context with a more specific data type.

```go title="Signature"
func Locals[V any](c Ctx, key any, value ...V) V
```

```go title="Example"
app.Use(func(c Ctx) error {
  fiber.Locals[string](c, "john", "doe")
  fiber.Locals[int](c, "age", 18)
  fiber.Locals[bool](c, "isHuman", true)
  return c.Next()
})
app.Get("/test", func(c Ctx) error {
  fiber.Locals[string](c, "john")     // "doe"
  fiber.Locals[int](c, "age")         // 18
  fiber.Locals[bool](c, "isHuman")    // true
  return nil
})
````

Make sure to understand and correctly implement the Locals method in both its standard and generic form for better control 
over route-specific data within your application.

## Next

When **Next** is called, it executes the next method in the stack that matches the current route. You can pass an error struct within the method that will end the chaining and call the [error handler](https://docs.gofiber.io/guide/error-handling).

```go title="Signature"
func (c Ctx) Next() error
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  fmt.Println("1st route!")
  return c.Next()
})

app.Get("*", func(c fiber.Ctx) error {
  fmt.Println("2nd route!")
  return c.Next()
})

app.Get("/", func(c fiber.Ctx) error {
  fmt.Println("3rd route!")
  return c.SendString("Hello, World!")
})
```


## Redirect

Returns the Redirect reference.

For detailed information check the [Redirect](./redirect.md) documentation.

```go title="Signature"
func (c Ctx) Redirect() *Redirect
```

```go title="Example"
app.Get("/coffee", func(c fiber.Ctx) error {
    return c.Redirect().To("/teapot")
})

app.Get("/teapot", func(c fiber.Ctx) error {
    return c.Status(fiber.StatusTeapot).Send("🍵 short and stout 🍵")
})
```

## Reset

Reset the context fields by given request when to use server handlers.

```go title="Signature"
func (c Ctx) Reset(fctx *fasthttp.RequestCtx)
```

It is used outside of the Fiber Handlers to reset the context for the next request.

## RestartRouting

Instead of executing the next method when calling [Next](ctx.md#next), **RestartRouting** restarts execution from the first method that matches the current route. This may be helpful after overriding the path, i.e. an internal redirect. Note that handlers might be executed again which could result in an infinite loop.

```go title="Signature"
func (c Ctx) RestartRouting() error
```

```go title="Example"
app.Get("/new", func(c fiber.Ctx) error {
  return c.SendString("From /new")
})

app.Get("/old", func(c fiber.Ctx) error {
  c.Path("/new")
  return c.RestartRouting()
})
```

## SaveFile

Method is used to save **any** multipart file to disk.

```go title="Signature"
func (c Ctx) SaveFile(fh *multipart.FileHeader, path string) error
```

```go title="Example"
app.Post("/", func(c fiber.Ctx) error {
  // Parse the multipart form:
  if form, err := c.MultipartForm(); err == nil {
    // => *multipart.Form

    // Get all files from "documents" key:
    files := form.File["documents"]
    // => []*multipart.FileHeader

    // Loop through files:
    for _, file := range files {
      fmt.Println(file.Filename, file.Size, file.Header["Content-Type"][0])
      // => "tutorial.pdf" 360641 "application/pdf"

      // Save the files to disk:
      if err := c.SaveFile(file, fmt.Sprintf("./%s", file.Filename)); err != nil {
        return err
      }
    }
    return err
  }
})
```

## SaveFileToStorage

Method is used to save **any** multipart file to an external storage system.

```go title="Signature"
func (c Ctx) SaveFileToStorage(fileheader *multipart.FileHeader, path string, storage Storage) error
```

```go title="Example"
storage := memory.New()

app.Post("/", func(c fiber.Ctx) error {
  // Parse the multipart form:
  if form, err := c.MultipartForm(); err == nil {
    // => *multipart.Form

    // Get all files from "documents" key:
    files := form.File["documents"]
    // => []*multipart.FileHeader

    // Loop through files:
    for _, file := range files {
      fmt.Println(file.Filename, file.Size, file.Header["Content-Type"][0])
      // => "tutorial.pdf" 360641 "application/pdf"

      // Save the files to storage:
      if err := c.SaveFileToStorage(file, fmt.Sprintf("./%s", file.Filename), storage); err != nil {
        return err
      }
    }
    return err
  }
})
```

## SetUserContext

Sets the user specified implementation for context interface.

```go title="Signature"
func (c Ctx) SetUserContext(ctx context.Context)
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  ctx := context.Background()
  c.SetUserContext(ctx)
  // Here ctx could be any context implementation

  // ...
})
```

## String

Returns unique string representation of the ctx.

```go title="Signature"
func (c Ctx) String() string
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.String() // => "#0000000100000001 - 127.0.0.1:3000 <-> 127.0.0.1:61516 - GET http://localhost:3000/"

  // ...
})
```

## UserContext

UserContext returns a context implementation that was set by user earlier
or returns a non-nil, empty context, if it was not set earlier.

```go title="Signature"
func (c Ctx) UserContext() context.Context
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  ctx := c.UserContext()
  // ctx is context implementation set by user

  // ...
})
```

## 📩 Request {#request}

### Accepts

Checks, if the specified **extensions** or **content** **types** are acceptable.

:::info
Based on the request’s [Accept](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept) HTTP header.
:::

```go title="Signature"
func (r *Request) Accepts(offers ...string)          string
func (r *Request) AcceptsCharsets(offers ...string)  string
func (r *Request) AcceptsEncodings(offers ...string) string
func (r *Request) AcceptsLanguages(offers ...string) string
```

```go title="Example"
// Accept: text/html, application/json; q=0.8, text/plain; q=0.5; charset="utf-8"

app.Get("/", func(c fiber.Ctx) error {
  c.Req().Accepts("html")             // "html"
  c.Req().Accepts("text/html")        // "text/html"
  c.Req().Accepts("json", "text")     // "json"
  c.Req().Accepts("application/json") // "application/json"
  c.Req().Accepts("text/plain", "application/json") // "application/json", due to quality
  c.Req().Accepts("image/png")        // ""
  c.Req().Accepts("png")              // ""
  c.Accepts("html") // "html"
  // ...
})
```

```go title="Example 2"
// Accept: text/html, text/*, application/json, */*; q=0

app.Get("/", func(c fiber.Ctx) error {
  c.Req().Accepts("text/plain", "application/json") // "application/json", due to specificity
  c.Req().Accepts("application/json", "text/html") // "text/html", due to first match
  c.Req().Accepts("image/png")        // "", due to */* without q factor 0 is Not Acceptable
  // ...
})
```

Media-Type parameters are supported.

```go title="Example 3"
// Accept: text/plain, application/json; version=1; foo=bar

app.Get("/", func(c fiber.Ctx) error {
  // Extra parameters in the accept are ignored
  c.Req().Accepts("text/plain;format=flowed") // "text/plain;format=flowed"
  
  // An offer must contain all parameters present in the Accept type
  c.Req().Accepts("application/json") // ""

  // Parameter order and capitalization does not matter. Quotes on values are stripped.
  c.Req().Accepts(`application/json;foo="bar";VERSION=1`) // "application/json;foo="bar";VERSION=1"
})
```

```go title="Example 4"
// Accept: text/plain;format=flowed;q=0.9, text/plain
// i.e., "I prefer text/plain;format=flowed less than other forms of text/plain"
app.Get("/", func(c fiber.Ctx) error {
  // Beware: the order in which offers are listed matters.
  // Although the client specified they prefer not to receive format=flowed,
  // the text/plain Accept matches with "text/plain;format=flowed" first, so it is returned.
  c.Req().Accepts("text/plain;format=flowed", "text/plain") // "text/plain;format=flowed"

  // Here, things behave as expected:
  c.Req().Accepts("text/plain", "text/plain;format=flowed") // "text/plain"
})
```

Fiber provides similar functions for the other accept headers.

```go
// Accept-Charset: utf-8, iso-8859-1;q=0.2
// Accept-Encoding: gzip, compress;q=0.2
// Accept-Language: en;q=0.8, nl, ru

app.Get("/", func(c fiber.Ctx) error {
  c.Req().AcceptsCharsets("utf-16", "iso-8859-1")
  // "iso-8859-1"

  c.Req().AcceptsEncodings("compress", "br")
  // "compress"

  c.Req().AcceptsLanguages("pt", "nl", "ru")
  // "nl"
  // ...
})
```

### BaseURL

Returns the base URL \(**protocol** + **host**\) as a `string`.

```go title="Signature"
func (r *Request) BaseURL() string
```

```go title="Example"
// GET https://example.com/page#chapter-1

app.Get("/", func(c fiber.Ctx) error {
  c.Req().BaseURL() // https://example.com
  c.BaseUrl()       // https://example.com
  // ...
})
```

### Body

As per the header `Content-Encoding`, this method will try to perform a file decompression from the **body** bytes. In case no `Content-Encoding` header is sent, it will perform as [BodyRaw](#bodyraw).

```go title="Signature"
func (r *Request) Body() []byte
```

```go title="Example"
// echo 'user=john' | gzip | curl -v -i --data-binary @- -H "Content-Encoding: gzip" http://localhost:8080

app.Post("/", func(c fiber.Ctx) error {
  // Decompress body from POST request based on the Content-Encoding and return the raw content:
  c.Req().Body()          // []byte("user=john")
  return c.Send(c.Body()) // []byte("user=john")
})
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::

### BodyRaw

Returns the raw request **body**.

```go title="Signature"
func (r *Request) BodyRaw() []byte
```

```go title="Example"
// curl -X POST http://localhost:8080 -d user=john

app.Post("/", func(c fiber.Ctx) error {
  // Get raw body from POST request:
  c.Req().BodyRaw()          // []byte("user=john")
  return c.Send(c.BodyRaw()) // []byte("user=john")
})
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::



### Cookies

Get cookie value by key, you could pass an optional default value that will be returned if the cookie key does not exist.

```go title="Signature"
func (r *Request) Cookies(key string, defaultValue ...string) string
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  // Get cookie by key:
  c.Req().Cookies("name")         // "john"
  c.Req().Cookies("empty", "doe") // "doe"
  c.Cookies("name")               // "john"
  // ...
})
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::

### Fresh

When the response is still **fresh** in the client's cache **true** is returned, otherwise **false** is returned to indicate that the client cache is now stale and the full response should be sent.

When a client sends the Cache-Control: no-cache request header to indicate an end-to-end reload request, `Fresh` will return false to make handling these requests transparent.

Read more on [https://expressjs.com/en/4x/api.html\#req.fresh](https://expressjs.com/en/4x/api.html#req.fresh)

```go title="Signature"
func (r *Request) Fresh() bool
```

### Get

Returns the HTTP request header specified by the field.

:::tip
The match is **case-insensitive**.
:::

```go title="Signature"
func (r *Request) Get(key string, defaultValue ...string) string
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Req().Get("Content-Type")       // "text/plain"
  c.Req().Get("CoNtEnT-TypE")       // "text/plain"
  c.Get("something", "john")        // "john"
  // ..
})
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::


### Host

Returns the host derived from the [Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) HTTP header.

In a network context, [`Host`](#host) refers to the combination of a hostname and potentially a port number used for connecting, while [`Hostname`](#hostname) refers specifically to the name assigned to a device on a network, excluding any port information.

```go title="Signature"
func (r *Request) Host() string
```

```go title="Example"
// GET http://google.com:8080/search

app.Get("/", func(c fiber.Ctx) error {
  c.Req().Host()     // "google.com:8080"
  c.Req().Hostname() // "google.com"
  c.Host()           // "google.com:8080"
  c.Hostname()       // "google.com"
  // ...
})
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::

### Hostname

Returns the hostname derived from the [Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) HTTP header.

```go title="Signature"
func (r *Request) Hostname() string
```

```go title="Example"
// GET http://google.com/search

app.Get("/", func(c fiber.Ctx) error {
  c.Req().Hostname() // "google.com"
  c.Hostname()       // "google.com"

  // ...
})
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::

### IP

Returns the remote IP address of the request.

```go title="Signature"
func (r *Request) IP() string
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Req().IP() // "127.0.0.1"
  c.IP()       // "127.0.0.1"

  // ...
})
```

When registering the proxy request header in the fiber app, the ip address of the header is returned [(Fiber configuration)](fiber.md#proxyheader)

```go
app := fiber.New(fiber.Config{
  ProxyHeader: fiber.HeaderXForwardedFor,
})
```

### IPs

Returns an array of IP addresses specified in the [X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For) request header.

```go title="Signature"
func (r *Request) IPs() []string
```

```go title="Example"
// X-Forwarded-For: proxy1, 127.0.0.1, proxy3

app.Get("/", func(c fiber.Ctx) error {
  c.Req().IPs() // ["proxy1", "127.0.0.1", "proxy3"]
  c.IPs()       // ["proxy1", "127.0.0.1", "proxy3"]

  // ...
})
```

:::caution
Improper use of the X-Forwarded-For header can be a security risk. For details, see the [Security and privacy concerns](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For#security_and_privacy_concerns) section.
:::

### Is

Returns the matching **content type**, if the incoming request’s [Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type) HTTP header field matches the [MIME type](https://developer.mozilla.org/ru/docs/Web/HTTP/Basics_of_HTTP/MIME_types) specified by the type parameter.

:::info
If the request has **no** body, it returns **false**.
:::

```go title="Signature"
func (r *Request) Is(extension string) bool
```

```go title="Example"
// Content-Type: text/html; charset=utf-8

app.Get("/", func(c fiber.Ctx) error {
  c.Req().Is("html")  // true
  c.Req().Is(".html") // true
  c.Req().Is("json")  // false
  c.Is("json")        // false

  // ...
})
```

### IsFromLocal

Returns true if request came from localhost

```go title="Signature"
func (r *Request) IsFromLocal() bool {
```

```go title="Example"

app.Get("/", func(c fiber.Ctx) error {
  // If request came from localhost, return true else return false
  c.Req().IsFromLocal()
  c.IsFromLocal()

  // ...
})
```

### Method

Returns a string corresponding to the HTTP method of the request: `GET`, `POST`, `PUT`, and so on.  
Optionally, you could override the method by passing a string.

```go title="Signature"
func (r *Request) Method(override ...string) string
```

```go title="Example"
app.Post("/", func(c fiber.Ctx) error {
  c.Req().Method() // "POST"

  c.Req().Method("GET")
  c.Method() // GET

  // ...
})
```

### MultipartForm

To access multipart form entries, you can parse the binary with `MultipartForm()`. This returns a `map[string][]string`, so given a key, the value will be a string slice.

```go title="Signature"
func (r *Request) MultipartForm() (*multipart.Form, error)
```

```go title="Example"
app.Post("/", func(c fiber.Ctx) error {
  // Parse the multipart form:
  if form, err := c.Req().MultipartForm(); err == nil { // Note: c.MultipartForm() also works.
    // => *multipart.Form

    if token := form.Value["token"]; len(token) > 0 {
      // Get key value:
      fmt.Println(token[0])
    }

    // Get all files from "documents" key:
    files := form.File["documents"]
    // => []*multipart.FileHeader

    // Loop through files:
    for _, file := range files {
      fmt.Println(file.Filename, file.Size, file.Header["Content-Type"][0])
      // => "tutorial.pdf" 360641 "application/pdf"

      // Save the files to disk:
      if err := c.SaveFile(file, fmt.Sprintf("./%s", file.Filename)); err != nil {
        return err
      }
    }
  }

  return err
})
```


### OriginalURL

Returns the original request URL.

```go title="Signature"
func (r *Request) OriginalURL() string
```

```go title="Example"
// GET http://example.com/search?q=something

app.Get("/", func(c fiber.Ctx) error {
  c.Req().OriginalURL() // "/search?q=something"
  c.OriginalURL()       // "/search?q=something"

  // ...
})
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::

### Params

Method can be used to get the route parameters, you could pass an optional default value that will be returned if the param key does not exist.

:::info
Defaults to empty string \(`""`\), if the param **doesn't** exist.
:::

```go title="Signature"
func (r *Request) Params(key string, defaultValue ...string) string
```

```go title="Example"
// GET http://example.com/user/fenny
app.Get("/user/:name", func(c fiber.Ctx) error {
  c.Req().Params("name") // "fenny"
  c.Params("name")       // "fenny"

  // ...
})

// GET http://example.com/user/fenny/123
app.Get("/user/*", func(c fiber.Ctx) error {
  c.Req().Params("*")  // "fenny/123"
  c.Req().Params("*1") // "fenny/123"
  c.Params("*1")       // "fenny/123"

  // ...
})
```

Unnamed route parameters\(\*, +\) can be fetched by the **character** and the **counter** in the route.

```go title="Example"
// ROUTE: /v1/*/shop/*
// GET:   /v1/brand/4/shop/blue/xs
c.Params("*1")  // "brand/4"
c.Params("*2")  // "blue/xs"
```

For reasons of **downward compatibility**, the first parameter segment for the parameter character can also be accessed without the counter.

```go title="Example"
app.Get("/v1/*/shop/*", func(c fiber.Ctx) error {
  c.Params("*") // outputs the values of the first wildcard segment
})
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::


In certain scenarios, it can be useful to have an alternative approach to handle different types of parameters, not 
just strings. This can be achieved using a generic Query function known as `Params[V GenericType](c Ctx, key string, defaultValue ...V) V`. 
This function is capable of parsing a query string and returning a value of a type that is assumed and specified by `V GenericType`.

```go title="Signature"
func Params[v GenericType](c Ctx, key string, default value ...V) V
```

```go title="Example"

// Get http://example.com/user/114
app.Get("/user/:id", func(c fiber.Ctx) error{
  fiber.Params[string](c, "id") // returns "114" as string.
  fiber.Params[int](c, "id") // returns 114 as integer
  fiber.Params[string](c, "number") // retunrs "" (default string type)
  fiber.Params[int](c, "number") // returns 0 (default integer value type)
})
```

The generic Params function supports returning the following data types based on V GenericType:
- Integer: int, int8, int16, int32, int64
- Unsigned integer: uint, uint8, uint16, uint32, uint64
- Floating-point numbers: float32, float64
- Boolean: bool
- String: string
- Byte array: []byte


### Path

Contains the path part of the request URL. Optionally, you could override the path by passing a string. For internal redirects, you might want to call [RestartRouting](ctx.md#restartrouting) instead of [Next](ctx.md#next).

```go title="Signature"
func (r *Request) Path(override ...string) string
```

```go title="Example"
// GET http://example.com/users?sort=desc

app.Get("/users", func(c fiber.Ctx) error {
  c.Req().Path() // "/users"

  c.Req().Path("/john")
  c.Req().Path() // "/john"
  c.Path()       // "/john"

  // ...
})
```

### Port

Returns the remote port of the request.

```go title="Signature"
func (r *Request) Port() string
```

```go title="Example"
// GET http://example.com:8080
app.Get("/", func(c fiber.Ctx) error {
  c.Req().Port() // "8080"
  c.Port()       // "8080"

  // ...
})
```

### Protocol

Contains the request protocol string: `http` or `https` for **TLS** requests.

```go title="Signature"
func (r *Request) Protocol() string
```

```go title="Example"
// GET http://example.com

app.Get("/", func(c fiber.Ctx) error {
  c.Req().Protocol() // "http"
  c.Protocol()       // "http"

  // ...
})
```

### Queries

Queries is a function that returns an object containing a property for each query string parameter in the route.

```go title="Signature"
func (r *Request) Queries() map[string]string
```

```go title="Example"
// GET http://example.com/?name=alex&want_pizza=false&id=

app.Get("/", func(c fiber.Ctx) error {
	m := c.Req().Queries()
	m["name"] // "alex"
	m["want_pizza"] // "false"
	m["id"] // ""
	// ...
})
```

```go title="Example"
// GET http://example.com/?field1=value1&field1=value2&field2=value3

app.Get("/", func (c fiber.Ctx) error {
	m := c.Queries()
	m["field1"] // "value2"
	m["field2"] // value3
})
```

```go title="Example"
// GET http://example.com/?list_a=1&list_a=2&list_a=3&list_b[]=1&list_b[]=2&list_b[]=3&list_c=1,2,3

app.Get("/", func(c fiber.Ctx) error {
	m := c.Req().Queries()
	m["list_a"] // "3"
	m["list_b[]"] // "3"
	m["list_c"] // "1,2,3"
})
```

```go title="Example"
// GET /api/posts?filters.author.name=John&filters.category.name=Technology

app.Get("/", func(c fiber.Ctx) error {
	m := c.Queries()
	m["filters.author.name"] // John
	m["filters.category.name"] // Technology
})
```

```go title="Example"
// GET /api/posts?tags=apple,orange,banana&filters[tags]=apple,orange,banana&filters[category][name]=fruits&filters.tags=apple,orange,banana&filters.category.name=fruits

app.Get("/", func(c fiber.Ctx) error {
	m := c.Req().Queries()
	m["tags"] // apple,orange,banana
	m["filters[tags]"] // apple,orange,banana
	m["filters[category][name]"] // fruits
	m["filters.tags"] // apple,orange,banana
	m["filters.category.name"] // fruits
})
```

### Query

This property is an object containing a property for each query string parameter in the route, you could pass an optional default value that will be returned if the query key does not exist.

:::info
If there is **no** query string, it returns an **empty string**.
:::

```go title="Signature"
func (c Ctx) Query(key string, defaultValue ...string) string
```

```go title="Example"
// GET http://example.com/?order=desc&brand=nike

app.Get("/", func(c fiber.Ctx) error {
  c.Req().Query("order")         // "desc"
  c.Query("brand")               // "nike"
  c.Req().Query("empty", "nike") // "nike"

  // ...
})
```

:::info

Returned value is only valid within the handler. Do not store any references.  
Make copies or use the [**`Immutable`**](./ctx.md) setting instead. [Read more...](../#zero-allocation)

:::

In certain scenarios, it can be useful to have an alternative approach to handle different types of query parameters, not 
just strings. This can be achieved using a generic Query function known as `Query[V GenericType](c Ctx, key string, defaultValue ...V) V`. 
This function is capable of parsing a query string and returning a value of a type that is assumed and specified by `V GenericType`.

Here is the signature for the generic Query function:

```go title="Signature"
func Query[V GenericType](c Ctx, key string, defaultValue ...V) V
```

Consider this example:

```go title="Example"
// GET http://example.com/?page=1&brand=nike&new=true

app.Get("/", func(c fiber.Ctx) error {
  fiber.Query[int](c, "page")     // 1
  fiber.Query[string](c, "brand") // "nike"
  fiber.Query[bool](c, "new")     // true

  // ...
})
```

In this case, `Query[V GenericType](c Ctx, key string, defaultValue ...V) V` can retrieve 'page' as an integer, 'brand' 
as a string, and 'new' as a boolean. The function uses the appropriate parsing function for each specified type to ensure 
the correct type is returned. This simplifies the retrieval process of different types of query parameters, making your 
controller actions cleaner.

The generic Query function supports returning the following data types based on V GenericType:
- Integer: int, int8, int16, int32, int64
- Unsigned integer: uint, uint8, uint16, uint32, uint64
- Floating-point numbers: float32, float64
- Boolean: bool
- String: string
- Byte array: []byte

### Range

A struct containing the type and a slice of ranges will be returned.

```go title="Signature"
func (r *Request) Range(size int) (Range, error)
```

```go title="Example"
// Range: bytes=500-700, 700-900
app.Get("/", func(c fiber.Ctx) error {
  b := c.Req().Range(1000) // c.Range also works
  if b.Type == "bytes" {
      for r := range r.Ranges {
      fmt.Println(r)
      // [500, 700]
    }
  }
})
```

### Route

Returns the matched [Route](https://pkg.go.dev/github.com/gofiber/fiber?tab=doc#Route) struct.

```go title="Signature"
func (r *Request) Route() *Route
```

```go title="Example"
// http://localhost:8080/hello


app.Get("/hello/:name", func(c fiber.Ctx) error {
  r := c.Req().Route()
  fmt.Println(r.Method, r.Path, r.Params, r.Handlers)
  // GET /hello/:name handler [name]

  // ...
})
```

:::caution
Do not rely on `c.Route()` in middlewares **before** calling `c.Next()` - `c.Route()` returns the **last executed route**.
:::

```go title="Example"
func MyMiddleware() fiber.Handler {
  return func(c fiber.Ctx) error {
    beforeNext := c.Route().Path // Will be '/'
    err := c.Next()
    afterNext := c.Route().Path // Will be '/hello/:name'
    return err
  }
}
```

### Scheme

Contains the request protocol string: http or https for TLS requests.

:::info
Please use [`Config.EnableTrustedProxyCheck`](fiber.md#enabletrustedproxycheck) to prevent header spoofing, in case when your app is behind the proxy.
:::

```go title="Signature"
func (r *Request) Scheme() string
```

```go title="Example"
// GET http://example.com
app.Get("/", func(c fiber.Ctx) error {
  c.Req().Scheme() // "http"
  c.Scheme()       // "http"

  // ...
})
```

### Secure

A boolean property that is `true` , if a **TLS** connection is established.

```go title="Signature"
func (r *Request) Secure() bool
```

```go title="Example"
// Secure() method is equivalent to:
c.Req().Protocol() == "https"
// or
c.Protocol() == "https"
```

### Stale

[https://expressjs.com/en/4x/api.html\#req.stale](https://expressjs.com/en/4x/api.html#req.stale)

```go title="Signature"
func (r *Request) Stale() bool
```

### Subdomains

Returns a string slice of subdomains in the domain name of the request.

The application property subdomain offset, which defaults to `2`, is used for determining the beginning of the subdomain segments.

```go title="Signature"
func (r *Request) Subdomains(offset ...int) []string
```

```go title="Example"
// Host: "tobi.ferrets.example.com"

app.Get("/", func(c fiber.Ctx) error {
  c.Req().Subdomains()  // ["ferrets", "tobi"]
  c.Req().Subdomains(1) // ["tobi"]
  c.Subdomains(1)       // ["tobi"]

  // ...
})
```

### XHR

A Boolean property, that is `true`, if the request’s [X-Requested-With](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers) header field is [XMLHttpRequest](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest), indicating that the request was issued by a client library \(such as [jQuery](https://api.jquery.com/jQuery.ajax/)\).

```go title="Signature"
func (r *Request) XHR() bool
```

```go title="Example"
// X-Requested-With: XMLHttpRequest

app.Get("/", func(c fiber.Ctx) error {
  c.Req().XHR() // true
  c.XHR()       // true

  // ...
})
```

## 📨 Response {#response}

### Append

Appends the specified **value** to the HTTP response header field.

:::caution
If the header is **not** already set, it creates the header with the specified value.
:::

```go title="Signature"
func (r *Response) Append(field string, values ...string)
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Res().Append("Link", "http://google.com", "http://localhost")
  // => Link: http://localhost, http://google.com

  c.Append("Link", "Test")
  // => Link: http://localhost, http://google.com, Test

  // ...
})
```

### Attachment

Sets the HTTP response [Content-Disposition](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition) header field to `attachment`.

```go title="Signature"
func (r *Response) Attachment(filename ...string)
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Res().Attachment()
  // => Content-Disposition: attachment

  c.Attachment("./upload/images/logo.png")
  // => Content-Disposition: attachment; filename="logo.png"
  // => Content-Type: image/png

  // ...
})
```

### AutoFormat

Performs content-negotiation on the [Accept](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept) HTTP header. It uses [Accepts](ctx.md#accepts) to select a proper format.
The supported content types are `text/html`, `text/plain`, `application/json`, and `application/xml`.
For more flexible content negotiation, use [Format](ctx.md#format).


:::info
If the header is **not** specified or there is **no** proper format, **text/plain** is used.
:::

```go title="Signature"
func (r *Response) AutoFormat(body any) error
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  // Accept: text/plain
  c.Res().AutoFormat("Hello, World!")
  // => Hello, World!

  // Accept: text/html
  c.AutoFormat("Hello, World!")
  // => <p>Hello, World!</p>

  type User struct {
    Name string
  }
  user := User{"John Doe"}

  // Accept: application/json
  c.Res().AutoFormat(user)
  // => {"Name":"John Doe"}

  // Accept: application/xml
  c.AutoFormat(user)
  // => <User><Name>John Doe</Name></User>
  // ..
})
```

### ClearCookie

Expire a client cookie \(_or all cookies if left empty\)_

```go title="Signature"
func (r *Response) ClearCookie(key ...string)
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  // Clears all cookies:
  c.Res().ClearCookie()

  // Expire specific cookie by name:
  c.Res().ClearCookie("user")

  // Expire multiple cookies by names:
  c.ClearCookie("token", "session", "track_id", "version")
  // ...
})
```

:::caution
Web browsers and other compliant clients will only clear the cookie if the given options are identical to those when creating the cookie, excluding expires and maxAge. ClearCookie will not set these values for you - a technique similar to the one shown below should be used to ensure your cookie is deleted.
:::

```go title="Example"
app.Get("/set", func(c fiber.Ctx) error {
    c.Cookie(&fiber.Cookie{
        Name:     "token",
        Value:    "randomvalue",
        Expires:  time.Now().Add(24 * time.Hour),
        HTTPOnly: true,
        SameSite: "lax",
    })

    // ...
})

app.Get("/delete", func(c fiber.Ctx) error {
    c.Cookie(&fiber.Cookie{
        Name:     "token",
        // Set expiry date to the past
        Expires:  time.Now().Add(-(time.Hour * 2)),
        HTTPOnly: true,
        SameSite: "lax",
    })

    // ...
})
```


### Cookie

Set cookie

```go title="Signature"
func (r *Response) Cookie(cookie *Cookie)
```

```go
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
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  // Create cookie
  cookie := new(fiber.Cookie)
  cookie.Name = "john"
  cookie.Value = "doe"
  cookie.Expires = time.Now().Add(24 * time.Hour)

  // Set cookie
  c.Res().Cookie(cookie) // c.Cookie also works
  // ...
})
```


### Download

Transfers the file from path as an `attachment`.

Typically, browsers will prompt the user to download. By default, the [Content-Disposition](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition) header `filename=` parameter is the file path \(_this typically appears in the browser dialog_\).

Override this default with the **filename** parameter.

```go title="Signature"
func (r *Response) Download(file string, filename ...string) error
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  return c.Res().Download("./files/report-12345.pdf");
  // => Download report-12345.pdf

  return c.Download("./files/report-12345.pdf", "report.pdf");
  // => Download report.pdf
})
```

### Format

Performs content-negotiation on the [Accept](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept) HTTP header. It uses [Accepts](ctx.md#accepts) to select a proper format from the supplied offers. A default handler can be provided by setting the `MediaType` to `"default"`. If no offers match and no default is provided, a 406 (Not Acceptable) response is sent. The Content-Type is automatically set when a handler is selected.

:::info
If the Accept header is **not** specified, the first handler will be used.
:::

```go title="Signature"
func (r *Response) Format(handlers ...ResFmt) error
```

```go title="Example"
// Accept: application/json => {"command":"eat","subject":"fruit"}
// Accept: text/plain => Eat Fruit!
// Accept: application/xml => Not Acceptable
app.Get("/no-default", func(c fiber.Ctx) error {
  return c.Res().Format(
    fiber.ResFmt{"application/json", func(c fiber.Ctx) error {
      return c.JSON(fiber.Map{
        "command": "eat",
        "subject": "fruit",
      })
    }},
    fiber.ResFmt{"text/plain", func(c fiber.Ctx) error {
      return c.SendString("Eat Fruit!")
    }},
  )
})

// Accept: application/json => {"command":"eat","subject":"fruit"}
// Accept: text/plain => Eat Fruit!
// Accept: application/xml => Eat Fruit!
app.Get("/default", func(c fiber.Ctx) error {
  textHandler := func(c fiber.Ctx) error {
    return c.SendString("Eat Fruit!")
  }

  handlers := []fiber.ResFmt{
    {"application/json", func(c fiber.Ctx) error {
      return c.JSON(fiber.Map{
        "command": "eat",
        "subject": "fruit",
      })
    }},
    {"text/plain", textHandler},
    {"default", textHandler},
  }

  return c.Format(handlers...)
})
```

### JSON

Converts any **interface** or **string** to JSON using the [encoding/json](https://pkg.go.dev/encoding/json) package.

:::info
JSON also sets the content header to the `ctype` parameter. If no `ctype` is passed in, the header is set to `application/json`.
:::

```go title="Signature"
func (r *Request) JSON(data any, ctype ...string) error
```

```go title="Example"
type SomeStruct struct {
  Name string
  Age  uint8
}

app.Get("/json", func(c fiber.Ctx) error {
  // Create data struct:
  data := SomeStruct{
    Name: "Grame",
    Age:  20,
  }

  return c.Res().JSON(data)
  // => Content-Type: application/json
  // => "{"Name": "Grame", "Age": 20}"

  return c.Res().JSON(fiber.Map{
    "name": "Grame",
    "age": 20,
  })
  // => Content-Type: application/json
  // => "{"name": "Grame", "age": 20}"

  return c.JSON(fiber.Map{
    "type": "https://example.com/probs/out-of-credit",
    "title": "You do not have enough credit.",
    "status": 403,
    "detail": "Your current balance is 30, but that costs 50.",
    "instance": "/account/12345/msgs/abc",
  }, "application/problem+json")
  // => Content-Type: application/problem+json
  // => "{
  // =>     "type": "https://example.com/probs/out-of-credit",
  // =>     "title": "You do not have enough credit.",
  // =>     "status": 403,
  // =>     "detail": "Your current balance is 30, but that costs 50.",
  // =>     "instance": "/account/12345/msgs/abc",
  // => }"
})
```

### JSONP

Sends a JSON response with JSONP support. This method is identical to [JSON](ctx.md#json), except that it opts-in to JSONP callback support. By default, the callback name is simply callback.

Override this by passing a **named string** in the method.

```go title="Signature"
func (r *Response) JSONP(data any, callback ...string) error
```

```go title="Example"
type SomeStruct struct {
  name string
  age  uint8
}

app.Get("/", func(c fiber.Ctx) error {
  // Create data struct:
  data := SomeStruct{
    name: "Grame",
    age:  20,
  }

  return c.Res().JSONP(data)
  // => callback({"name": "Grame", "age": 20})

  return c.JSONP(data, "customFunc")
  // => customFunc({"name": "Grame", "age": 20})
})
```

### Links

Joins the links followed by the property to populate the response’s [Link](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link) HTTP header field.

```go title="Signature"
func (r *Response) Links(link ...string)
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Res().Links(
    "http://api.example.com/users?page=2", "next",
    "http://api.example.com/users?page=5", "last",
  )
  c.Links(
    "http://api.example.com/users?page=2", "next",
    "http://api.example.com/users?page=5", "last",
  )
  // Link: <http://api.example.com/users?page=2>; rel="next",
  //       <http://api.example.com/users?page=5>; rel="last"

  // ...
})
```

### Location

Sets the response [Location](https://developer.mozilla.org/ru/docs/Web/HTTP/Headers/Location) HTTP header to the specified path parameter.

```go title="Signature"
func (r *Response) Location(path string)
```

```go title="Example"
app.Post("/", func(c fiber.Ctx) error {
  c.Res().Location("http://example.com")
  c.Location("/foo/bar")

  return nil
})
```


### Render

Renders a view with data and sends a `text/html` response. By default `Render` uses the default [**Go Template engine**](https://pkg.go.dev/html/template/). If you want to use another View engine, please take a look at our [**Template middleware**](https://docs.gofiber.io/template).

```go title="Signature"
func (r *Response) Render(name string, bind Map, layouts ...string) error
```

### Send

Sets the HTTP response body.

```go title="Signature"
func (r *Response) Send(body []byte) error
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  return c.Res().Send([]byte("Hello, World!")) // => "Hello, World!"

  return c.Send([]byte("Hello, World!")) // => "Hello, World!"
})
```

Fiber also provides `SendString` and `SendStream` methods for raw inputs.

:::tip
Use this if you **don't need** type assertion, recommended for **faster** performance.
:::

```go title="Signature"
func (r *Response) SendString(body string) error
func (r *Response) SendStream(stream io.Reader, size ...int) error
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  return c.Res().SendString("Hello, World!")
  // => "Hello, World!"

  return c.SendStream(bytes.NewReader([]byte("Hello, World!")))
  // => "Hello, World!"
})
```

### SendFile

Transfers the file from the given path. Sets the [Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type) response HTTP header field based on the **filenames** extension.

:::caution
Method doesn´t use **gzipping** by default, set it to **true** to enable.
:::

```go title="Signature" title="Signature"
func (r *Response) SendFile(file string, compress ...bool) error
```

```go title="Example"
app.Get("/not-found", func(c fiber.Ctx) error {
  return c.Res().SendFile("./public/404.html");

  // Disable compression
  return c.SendFile("./static/index.html", false);
})
```

:::info
If the file contains an url specific character you have to escape it before passing the file path into the `sendFile` function.
:::

```go title="Example"
app.Get("/file-with-url-chars", func(c fiber.Ctx) error {
  return c.SendFile(url.PathEscape("hash_sign_#.txt"))
})
```

:::info
For sending files from embedded file system [this functionality](../middleware/filesystem.md#sendfile) can be used
:::

### SendStatus

Sets the status code and the correct status message in the body, if the response body is **empty**.

:::tip
You can find all used status codes and messages [here](https://github.com/gofiber/fiber/blob/dffab20bcdf4f3597d2c74633a7705a517d2c8c2/utils.go#L183-L244).
:::

```go title="Signature"
func (r *Response) SendStatus(status int) error
```

```go title="Example"
app.Get("/not-found", func(c fiber.Ctx) error {
  return c.Res().SendStatus(415)
  // => 415 "Unsupported Media Type"

  c.SendString("Hello, World!")
  return c.SendStatus(415)
  // => 415 "Hello, World!"
})
```

### SendStream

Sets response body to a stream of data and add optional body size.

```go title="Signature"
func (r *Response) SendStream(stream io.Reader, size ...int) error
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  return c.Res().SendStream(bytes.NewReader([]byte("Hello, World!")))
  // => "Hello, World!"
})
```

### SendString

Sets the response body to a string.

```go title="Signature"
func (r *Response) SendString(body string) error
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  return c.Res().SendString("Hello, World!")
  // => "Hello, World!"
})
```

### Set

Sets the response’s HTTP header field to the specified `key`, `value`.

```go title="Signature"
func (r *Response) Set(key string, val string)
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Res().Set("Content-Type", "text/plain")
  // => "Content-Type: text/plain"

  c.Set("Keep-Alive", "timeout=5")
  // => "Keep-Alive: timeout=5"

  // ...
})
```

### Status

Sets the HTTP status for the response.

:::info
Method is a **chainable**.
:::

```go title="Signature"
func (r *Response) Status(status int) Ctx
```

```go title="Example"
app.Get("/fiber", func(c fiber.Ctx) error {
  c.Res().Status(fiber.StatusOK)
  return nil
}

app.Get("/hello", func(c fiber.Ctx) error {
  return c.Res().Status(fiber.StatusBadRequest).SendString("Bad Request")
}

app.Get("/world", func(c fiber.Ctx) error {
  return c.Status(fiber.StatusNotFound).SendFile("./public/gopher.png")
})
```

### Type

Sets the [Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type) HTTP header to the MIME type listed [here](https://github.com/nginx/nginx/blob/master/conf/mime.types) specified by the file **extension**.

:::info
Method is a **chainable**.
:::

```go title="Signature"
func (r *Response) Type(ext string, charset ...string) Ctx
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Res().Type(".html")    // => "text/html"
  c.Res().Type("html")     // => "text/html"
  c.Type("png")            // => "image/png"
  c.Type("json", "utf-8")  // => "application/json; charset=utf-8"

  // ...
})
```

### Vary

Adds the given header field to the [Vary](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary) response header. This will append the header, if not already listed, otherwise leaves it listed in the current location.

:::info
Multiple fields are **allowed**.
:::

```go title="Signature"
func (r *Response) Vary(fields ...string)
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Res().Vary("Origin")     // => Vary: Origin
  c.Vary("User-Agent")       // => Vary: Origin, User-Agent

  // No duplicates
  c.Res().Vary("Origin") // => Vary: Origin, User-Agent

  c.Res().Vary("Accept-Encoding", "Accept")
  // => Vary: Origin, User-Agent, Accept-Encoding, Accept

  // ...
})
```

### ViewBind

Add vars to default view var map binding to template engine.
Variables are read by the Render method and may be overwritten.

```go title="Signature"
func (r *Response) ViewBind(vars Map) error
```

```go title="Example"
app.Use(func(c fiber.Ctx) error {
  c.Res().ViewBind(fiber.Map{
    "Title": "Hello, World!",
  })
})

app.Get("/", func(c fiber.Ctx) error {
  return c.Res().Render("xxx.tmpl", fiber.Map{}) // Render will use Title variable
})
```

### Write

Write adopts the Writer interface

```go title="Signature"
func (r *Response) Write(p []byte) (n int, err error)
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Res().Write([]byte("Hello, World!")) // => "Hello, World!"

  fmt.Fprintf(c, "%s\n", "Hello, World!") // "Hello, World!Hello, World!"
})
```

### Writef

Writef adopts the string with variables

```go title="Signature"
func (r *Response) Writef(f string, a ...any) (n int, err error)
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  world := "World!"
  c.Res().Writef("Hello, %s", world) // => "Hello, World!"

  fmt.Fprintf(c, "%s\n", "Hello, World!") // "Hello, World!Hello, World!"
})
```

### WriteString

WriteString adopts the string

```go title="Signature"
func (r *Response) WriteString(s string) (n int, err error)
```

```go title="Example"
app.Get("/", func(c fiber.Ctx) error {
  c.Res().WriteString("Hello, World!") // => "Hello, World!"

  fmt.Fprintf(c, "%s\n", "Hello, World!") // "Hello, World!Hello, World!"
})
```

### XML

Converts any **interface** or **string** to XML using the standard `encoding/xml` package.

:::info
XML also sets the content header to **application/xml**.
:::

```go title="Signature"
func (r *Response) XML(data any) error
```

```go title="Example"
type SomeStruct struct {
  XMLName xml.Name `xml:"Fiber"`
  Name    string   `xml:"Name"`
  Age     uint8    `xml:"Age"`
}

app.Get("/", func(c fiber.Ctx) error {
  // Create data struct:
  data := SomeStruct{
    Name: "Grame",
    Age:  20,
  }

  return c.Res().XML(data) // c.XML also works
  // <Fiber>
  //     <Name>Grame</Name>
  //    <Age>20</Age>
  // </Fiber>
})
```
