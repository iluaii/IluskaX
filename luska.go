package main

import (
	"fmt"
	"net/http"
	"net/url"
	"golang.org/x/net/html"
	"flag"
	"strings"
	//"os"
	//"io"
)
type Form struct {
Action string
Method string
Inputs []string
}

func traverse(n *html.Node, base *url.URL, links *[]string, forms *[]Form) {
    if n.Type == html.ElementNode {
        switch n.Data {
        case "a":
            for _, attr := range n.Attr {
                if attr.Key == "href" {
                    link, err := url.Parse(attr.Val)
                    if err == nil {
                        *links = append(*links, base.ResolveReference(link).String())
                    }
                }
            }
        case "form":
            var f Form
            for _, attr := range n.Attr {
                switch attr.Key {
                case "action":
                    link, err := url.Parse(attr.Val)
                    if err == nil {
                        f.Action = base.ResolveReference(link).String()
                    }
                case "method":
                    f.Method = strings.ToUpper(attr.Val)
                }
            }
            if f.Method == "" {
                f.Method = "GET"
            }
            var collectInputs func(*html.Node)
            collectInputs = func(node *html.Node) {
                if node.Type == html.ElementNode {
                    switch node.Data {
                    case "input", "textarea", "select":
                        name, typ := "", node.Data
                        for _, a := range node.Attr {
                            if a.Key == "name" { name = a.Val }
                            if a.Key == "type" { typ = a.Val }
                        }
                        if name != "" {
                            f.Inputs = append(f.Inputs, typ+"="+name)
                        }
                    }
                }
                for c := node.FirstChild; c != nil; c = c.NextSibling {
                    collectInputs(c)
                }
            }
            collectInputs(n)
            *forms = append(*forms, f)
        }
    }
    for c := n.FirstChild; c != nil; c = c.NextSibling {
        traverse(c, base, links, forms)
    }
}

func pars(uri string) {
	req,err := http.Get(uri)
	if !strings.HasSuffix(uri, "/") {
		uri += "/"
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	defer req.Body.Close()

	doc,err := html.Parse(req.Body)

	if err != nil {
    fmt.Println(err)
    return
	}


	base,_ := url.Parse(uri)
	var links []string
	var forms []Form
	traverse(doc, base, &links, &forms)
	fmt.Println(base.Path)
	for _, l := range links {
		parsed, _ := url.Parse(l)
		if parsed.Path != "" {
			fmt.Println("|---" + parsed.Path)
			if parsed.RawQuery != "" {
				for key, vals := range parsed.Query() {
					fmt.Println("    |---[param] " + key + "=" + vals[0])
				}
			}
		}
	}
	for _, f := range forms {
		fmt.Printf("|---[form] %s %s\n", f.Method, f.Action)
		for _, inp := range f.Inputs {
			fmt.Println("    |---[field] " + inp)
		}
	}
}



func main() {
	u := flag.String("u","","url")
	//r := flag.Bool("r",false,"recursion")
	//rd := flag.Int("rd",0,"recursion depth")
	flag.Parse()

	
	
	pars(*u)
}