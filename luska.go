package main

import (
	"fmt"
	"net/http"
	"net/url"
	"golang.org/x/net/html"
	"flag"
	"strings"
	"os"
    "time"
	"io"
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

func pars(uri string,recurs bool,depr, depth int, term io.Writer, file io.Writer) {
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
	fmt.Fprintf(term,"\n%s\n",base.Path)
    for _, f := range forms {
  
        fmt.Fprintf(term, "|---[form] %s %s\n", f.Method, f.Action)
        
        var params []string
        for _, inp := range f.Inputs {
            fmt.Fprintln(term, "|   |---[field] "+inp)
            
            parts := strings.Split(inp, "=")
            if len(parts) > 1 {
                params = append(params, parts[1]+"=1") 
            }
        }

        if len(params) > 0 {
            connector := "?"
            if strings.Contains(f.Action, "?") {
                connector = "&"
            }
            fullFormUrl := f.Action + connector + strings.Join(params, "&")
            fmt.Fprintln(file, fullFormUrl) 
        }
    }
	for _, l := range links {
		parsed, _ := url.Parse(l)
		if parsed.Path != "" {
			fmt.Fprintln(term,"|---" + parsed.Path)
            fmt.Fprintln(file, parsed.Scheme+"://"+parsed.Host+parsed.Path)
			if parsed.RawQuery != "" {
				for key, vals := range parsed.Query() {
					fmt.Fprintln(term,"|   |---[param] " + key + "=" + vals[0])
				}
                fmt.Fprintln(file, parsed.Scheme+"://"+parsed.Host+parsed.Path+"?"+parsed.RawQuery)
			}
            if recurs && depr < depth {
                pars(l, recurs, depr+1, depth,term,file)
            }
		}
	}
	
}



func main() {
	u := flag.String("u","","url")
	r := flag.Bool("r",false,"recursion")
	rd := flag.Int("rd",0,"recursion depth")
	flag.Parse()

    if *u == "" {
        fmt.Println("ERROR: please enter url")
        return
    }

	parsed, _ := url.Parse(*u)
    date := time.Now().Format("2006-01-02_15-04-05")
    filename := "output/" + parsed.Hostname() + "|" + date + ".txt"
    f, err := os.Create(filename)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer f.Close()

	pars(*u,*r,0,*rd,os.Stdout,f)
}
