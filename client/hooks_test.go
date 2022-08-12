package client

import (
	"encoding/xml"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/utils"
)

func Test_AddMissing_Port(t *testing.T) {
	type args struct {
		addr  string
		isTLS bool
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "do anything",
			args: args{
				addr: "example.com:1234",
			},
			want: "example.com:1234",
		},
		{
			name: "add 80 port",
			args: args{
				addr: "example.com",
			},
			want: "example.com:80",
		},
		{
			name: "add 443 port",
			args: args{
				addr:  "example.com",
				isTLS: true,
			},
			want: "example.com:443",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			utils.AssertEqual(t, tt.want, addMissingPort(tt.args.addr, tt.args.isTLS))
		})
	}
}

func Test_Rand_String(t *testing.T) {
	tests := []struct {
		name string
		args int
	}{
		{
			name: "test generate",
			args: 16,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := randString(tt.args)
			utils.AssertEqual(t, 16, len(got))
		})
	}
}

func Test_Parser_Request_URL(t *testing.T) {
	t.Parallel()

	t.Run("client baseurl should be set", func(t *testing.T) {
		client := AcquireClient().SetBaseURL("http://example.com/api")
		req := AcquireRequest().SetURL("")

		err := parserRequestURL(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, "http://example.com/api", req.rawRequest.URI().String())
	})

	t.Run("request url should be set", func(t *testing.T) {
		client := AcquireClient()
		req := AcquireRequest().SetURL("http://example.com/api")

		err := parserRequestURL(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, "http://example.com/api", req.rawRequest.URI().String())
	})

	t.Run("the request url will override baseurl with protocol", func(t *testing.T) {
		client := AcquireClient().SetBaseURL("http://example.com/api")
		req := AcquireRequest().SetURL("http://example.com/api/v1")

		err := parserRequestURL(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, "http://example.com/api/v1", req.rawRequest.URI().String())
	})

	t.Run("the request url should be append after baseurl without protocol", func(t *testing.T) {
		client := AcquireClient().SetBaseURL("http://example.com/api")
		req := AcquireRequest().SetURL("/v1")

		err := parserRequestURL(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, "http://example.com/api/v1", req.rawRequest.URI().String())
	})

	t.Run("the url is error", func(t *testing.T) {
		client := AcquireClient().SetBaseURL("example.com/api")
		req := AcquireRequest().SetURL("/v1")

		err := parserRequestURL(client, req)
		utils.AssertEqual(t, ErrURLForamt, err)
	})

	t.Run("the path param from client", func(t *testing.T) {
		client := AcquireClient().
			SetBaseURL("http://example.com/api/:id").
			SetPathParam("id", "5")
		req := AcquireRequest()

		err := parserRequestURL(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, "http://example.com/api/5", req.rawRequest.URI().String())
	})

	t.Run("the path param from request", func(t *testing.T) {
		client := AcquireClient().
			SetBaseURL("http://example.com/api/:id/:name").
			SetPathParam("id", "5")
		req := AcquireRequest().
			SetURL("/{key}").
			SetPathParams(map[string]string{
				"name": "fiber",
				"key":  "val",
			}).
			DelPathParams("key")

		err := parserRequestURL(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, "http://example.com/api/5/fiber/%7Bkey%7D", req.rawRequest.URI().String())
	})

	t.Run("the path param from request and client", func(t *testing.T) {
		client := AcquireClient().
			SetBaseURL("http://example.com/api/:id/:name").
			SetPathParam("id", "5")
		req := AcquireRequest().
			SetURL("/:key").
			SetPathParams(map[string]string{
				"name": "fiber",
				"key":  "val",
				"id":   "12",
			})

		err := parserRequestURL(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, "http://example.com/api/12/fiber/val", req.rawRequest.URI().String())
	})

	t.Run("query params from client should be set", func(t *testing.T) {
		client := AcquireClient().
			SetParam("foo", "bar")
		req := AcquireRequest().SetURL("http://example.com/api/v1")

		err := parserRequestURL(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("foo=bar"), req.rawRequest.URI().QueryString())
	})

	t.Run("query params from request should be set", func(t *testing.T) {
		client := AcquireClient()
		req := AcquireRequest().
			SetURL("http://example.com/api/v1").
			SetParam("bar", "foo")

		err := parserRequestURL(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("bar=foo"), req.rawRequest.URI().QueryString())
	})

	t.Run("query params should be merged", func(t *testing.T) {
		client := AcquireClient().
			SetParam("bar", "foo1")
		req := AcquireRequest().
			SetURL("http://example.com/api/v1?bar=foo2").
			SetParam("bar", "foo")

		err := parserRequestURL(client, req)
		utils.AssertEqual(t, nil, err)

		values, _ := url.ParseQuery(string(req.rawRequest.URI().QueryString()))

		flag1, flag2, flag3 := false, false, false
		for _, v := range values["bar"] {
			if v == "foo1" {
				flag1 = true
			} else if v == "foo2" {
				flag2 = true
			} else if v == "foo" {
				flag3 = true
			}
		}
		utils.AssertEqual(t, true, flag1)
		utils.AssertEqual(t, true, flag2)
		utils.AssertEqual(t, true, flag3)
	})
}

func Test_Parser_Request_Header(t *testing.T) {
	t.Parallel()

	t.Run("client header should be set", func(t *testing.T) {
		client := AcquireClient().
			SetHeaders(map[string]string{
				fiber.HeaderContentType: "application/json",
			})

		req := AcquireRequest()

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("application/json"), req.rawRequest.Header.ContentType())
	})

	t.Run("request header should be set", func(t *testing.T) {
		client := AcquireClient()

		req := AcquireRequest().
			SetHeaders(map[string]string{
				fiber.HeaderContentType: "application/json, utf-8",
			})

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("application/json, utf-8"), req.rawRequest.Header.ContentType())
	})

	t.Run("request header should override client header", func(t *testing.T) {
		client := AcquireClient().
			SetHeader(fiber.HeaderContentType, "application/xml")

		req := AcquireRequest().
			SetHeader(fiber.HeaderContentType, "application/json, utf-8")

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("application/json, utf-8"), req.rawRequest.Header.ContentType())
	})

	t.Run("auto set json header", func(t *testing.T) {
		type jsonData struct {
			Name string `json:"name"`
		}
		client := AcquireClient()
		req := AcquireRequest().
			SetJSON(jsonData{
				Name: "foo",
			})

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte(applicationJSON), req.rawRequest.Header.ContentType())
	})

	t.Run("auto set xml header", func(t *testing.T) {
		type xmlData struct {
			XMLName xml.Name `xml:"body"`
			Name    string   `xml:"name"`
		}
		client := AcquireClient()
		req := AcquireRequest().
			SetXML(xmlData{
				Name: "foo",
			})

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte(applicationXML), req.rawRequest.Header.ContentType())
	})

	t.Run("auto set form data header", func(t *testing.T) {
		client := AcquireClient()
		req := AcquireRequest().
			SetFormDatas(map[string]string{
				"foo":  "bar",
				"ball": "cricle and square",
			})

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, applicationForm, string(req.rawRequest.Header.ContentType()))
	})

	t.Run("auto set file header", func(t *testing.T) {
		client := AcquireClient()
		req := AcquireRequest().
			AddFileWithReader("hello", io.NopCloser(strings.NewReader("world"))).
			SetFormData("foo", "bar")

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, true, strings.Contains(string(req.rawRequest.Header.MultipartFormBoundary()), "--FiberFormBoundary"))
		utils.AssertEqual(t, true, strings.Contains(string(req.rawRequest.Header.ContentType()), multipartFormData))
	})

	t.Run("ua should have default value", func(t *testing.T) {
		client := AcquireClient()
		req := AcquireRequest()

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("fiber"), req.rawRequest.Header.UserAgent())
	})

	t.Run("ua in client should be set", func(t *testing.T) {
		client := AcquireClient().SetUserAgent("foo")
		req := AcquireRequest()

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("foo"), req.rawRequest.Header.UserAgent())
	})

	t.Run("ua in request should have higher level", func(t *testing.T) {
		client := AcquireClient().SetUserAgent("foo")
		req := AcquireRequest().SetUserAgent("bar")

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("bar"), req.rawRequest.Header.UserAgent())
	})

	t.Run("referer in client should be set", func(t *testing.T) {
		client := AcquireClient().SetReferer("https://example.com")
		req := AcquireRequest()

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("https://example.com"), req.rawRequest.Header.Referer())
	})

	t.Run("referer in request should have higher level", func(t *testing.T) {
		client := AcquireClient().SetReferer("http://example.com")
		req := AcquireRequest().SetReferer("https://example.com")

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("https://example.com"), req.rawRequest.Header.Referer())
	})

	t.Run("client cookie should be set", func(t *testing.T) {
		client := AcquireClient().
			SetCookie("foo", "bar").
			SetCookies(map[string]string{
				"bar":  "foo",
				"bar1": "foo1",
			}).
			DelCookies("bar1")

		req := AcquireRequest()

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, "bar", string(req.rawRequest.Header.Cookie("foo")))
		utils.AssertEqual(t, "foo", string(req.rawRequest.Header.Cookie("bar")))
		utils.AssertEqual(t, "", string(req.rawRequest.Header.Cookie("bar1")))
	})

	t.Run("request cookie should be set", func(t *testing.T) {
		type cookies struct {
			Foo string `cookie:"foo"`
			Bar int    `cookie:"bar"`
		}

		client := AcquireClient()

		req := AcquireRequest().
			SetCookiesWithStruct(&cookies{
				Foo: "bar",
				Bar: 67,
			})

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, "bar", string(req.rawRequest.Header.Cookie("foo")))
		utils.AssertEqual(t, "67", string(req.rawRequest.Header.Cookie("bar")))
		utils.AssertEqual(t, "", string(req.rawRequest.Header.Cookie("bar1")))
	})

	t.Run("request cookie will override client cookie", func(t *testing.T) {
		type cookies struct {
			Foo string `cookie:"foo"`
			Bar int    `cookie:"bar"`
		}

		client := AcquireClient().
			SetCookie("foo", "bar").
			SetCookies(map[string]string{
				"bar":  "foo",
				"bar1": "foo1",
			})

		req := AcquireRequest().
			SetCookiesWithStruct(&cookies{
				Foo: "bar",
				Bar: 67,
			})

		err := parserRequestHeader(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, "bar", string(req.rawRequest.Header.Cookie("foo")))
		utils.AssertEqual(t, "67", string(req.rawRequest.Header.Cookie("bar")))
		utils.AssertEqual(t, "foo1", string(req.rawRequest.Header.Cookie("bar1")))
	})
}

func Test_Parser_Request_Body(t *testing.T) {
	t.Parallel()

	t.Run("json body", func(t *testing.T) {
		type jsonData struct {
			Name string `json:"name"`
		}
		client := AcquireClient()
		req := AcquireRequest().
			SetJSON(jsonData{
				Name: "foo",
			})

		err := parserRequestBody(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("{\"name\":\"foo\"}"), req.rawRequest.Body())
	})

	t.Run("xml body", func(t *testing.T) {
		type xmlData struct {
			XMLName xml.Name `xml:"body"`
			Name    string   `xml:"name"`
		}
		client := AcquireClient()
		req := AcquireRequest().
			SetXML(xmlData{
				Name: "foo",
			})

		err := parserRequestBody(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("<body><name>foo</name></body>"), req.rawRequest.Body())
	})

	t.Run("form data body", func(t *testing.T) {
		client := AcquireClient()
		req := AcquireRequest().
			SetFormDatas(map[string]string{
				"ball": "cricle and square",
			})

		err := parserRequestBody(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, "ball=cricle+and+square", string(req.rawRequest.Body()))
	})

	t.Run("file body", func(t *testing.T) {
		client := AcquireClient()
		req := AcquireRequest().
			AddFileWithReader("hello", io.NopCloser(strings.NewReader("world")))

		err := parserRequestBody(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, true, strings.Contains(string(req.rawRequest.Body()), "----FiberFormBoundary"))
		utils.AssertEqual(t, true, strings.Contains(string(req.rawRequest.Body()), "world"))
	})

	t.Run("file and form data", func(t *testing.T) {
		client := AcquireClient()
		req := AcquireRequest().
			AddFileWithReader("hello", io.NopCloser(strings.NewReader("world"))).
			SetFormData("foo", "bar")

		err := parserRequestBody(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, true, strings.Contains(string(req.rawRequest.Body()), "----FiberFormBoundary"))
		utils.AssertEqual(t, true, strings.Contains(string(req.rawRequest.Body()), "world"))
		utils.AssertEqual(t, true, strings.Contains(string(req.rawRequest.Body()), "bar"))
	})

	t.Run("raw body", func(t *testing.T) {
		client := AcquireClient()
		req := AcquireRequest().
			SetRawBody([]byte("hello world"))

		err := parserRequestBody(client, req)
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, []byte("hello world"), req.rawRequest.Body())
	})
}
