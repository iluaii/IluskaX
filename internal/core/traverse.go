package core

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

type Form struct {
	Action string
	Method string
	Inputs []string
}

func IsStaticAsset(path string) bool {
	staticExts := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
		".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz",
	}
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func IsSkipped(uri string, skipList []string) bool {
	for _, s := range skipList {
		if s != "" && strings.Contains(uri, s) {
			return true
		}
	}
	return false
}

func Traverse(n *html.Node, base *url.URL, links *[]string, forms *[]Form) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "a":
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					if link, err := url.Parse(attr.Val); err == nil {
						resolved := base.ResolveReference(link)
						resolved.Fragment = ""
						*links = append(*links, resolved.String())
					}
				}
			}

		case "script", "iframe":
			for _, attr := range n.Attr {
				if attr.Key == "src" && attr.Val != "" {
					if link, err := url.Parse(attr.Val); err == nil {
						*links = append(*links, base.ResolveReference(link).String())
					}
				}
			}

		case "form":
			f := parseForm(n, base)
			*forms = append(*forms, f)
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		Traverse(child, base, links, forms)
	}
}

func parseForm(n *html.Node, base *url.URL) Form {
	var f Form
	for _, attr := range n.Attr {
		switch attr.Key {
		case "action":
			if link, err := url.Parse(attr.Val); err == nil {
				f.Action = base.ResolveReference(link).String()
			}
		case "method":
			f.Method = strings.ToUpper(attr.Val)
		}
	}
	if f.Method == "" {
		f.Method = "GET"
	}
	if f.Action == "" {
		f.Action = base.String()
	}
	collectInputs(n, &f)
	return f
}

func collectInputs(n *html.Node, f *Form) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "input", "textarea", "select", "button":
			name, typ := "", n.Data
			for _, a := range n.Attr {
				if a.Key == "name" {
					name = a.Val
				}
				if a.Key == "type" && (n.Data == "input" || n.Data == "button") {
					typ = a.Val
				}
			}
			if name == "" {
				for _, a := range n.Attr {
					if a.Key == "id" {
						name = a.Val
						break
					}
				}
			}
			if name != "" {
				f.Inputs = append(f.Inputs, typ+"="+name)
			}
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		collectInputs(child, f)
	}
}
