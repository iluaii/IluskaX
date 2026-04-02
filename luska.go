package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/net/html"
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
					case "input", "textarea", "select", "button":
						name, typ := "", node.Data
						for _, a := range node.Attr {
							if a.Key == "name" {
								name = a.Val
							}
							if a.Key == "type" && (node.Data == "input" || node.Data == "button") {
								typ = a.Val
							}
						}
						if name == "" {
							for _, a := range node.Attr {
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

func isSkipped(uri string, skipList []string) bool {
	for _, s := range skipList {
		if s != "" && strings.Contains(uri, s) {
			return true
		}
	}
	return false
}

func pars(uri string, recurs bool, depr, depth int, term io.Writer, file io.Writer, visited map[string]bool, skipList []string) {
	if visited[uri] {
		return
	}
	visited[uri] = true

	if !strings.HasSuffix(uri, "/") {
		uri += "/"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := client.Get(uri)
	if err != nil {
		fmt.Fprintf(term, "  [ERROR] Failed to fetch %s: %v\n", uri, err)
		return
	}
	defer req.Body.Close()

	if req.StatusCode != 200 {
		fmt.Fprintf(term, "  [WARN] HTTP %d: %s\n", req.StatusCode, uri)
	}

	doc, err := html.Parse(req.Body)
	if err != nil {
		fmt.Fprintf(term, "  [ERROR] Failed to parse HTML: %v\n", err)
		return
	}

	base, err := url.Parse(uri)
	if err != nil {
		fmt.Fprintf(term, "  [ERROR] Invalid URL: %v\n", err)
		return
	}

	var links []string
	var forms []Form
	traverse(doc, base, &links, &forms)

	fmt.Fprintf(term, "\n[CRAWL] %s (Depth: %d)\n", base.Path, depr)
	fmt.Fprintf(term, "├─ Status: OK, Forms: %d, Links: %d\n", len(forms), len(links))

	if len(forms) > 0 {
		fmt.Fprintf(term, "├─ FORMS:\n")
		for i, f := range forms {
			fmt.Fprintf(term, "│  ├─ [%d] %s %s\n", i+1, f.Method, f.Action)
			var params []string
			for _, inp := range f.Inputs {
				parts := strings.Split(inp, "=")
				fmt.Fprintf(term, "│  │  ├─ %s\n", inp)
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
	}

	if len(links) > 0 {
		fmt.Fprintf(term, "├─ LINKS:\n")
		for i, l := range links {
			parsed, _ := url.Parse(l)
			if parsed.Path != "" && parsed.Host != "" {
				if isSkipped(l, skipList) {
					fmt.Fprintf(term, "│  ├─ [%d] %s [SKIPPED]\n", i+1, parsed.Path)
					continue
				}
				fmt.Fprintf(term, "│  ├─ [%d] %s\n", i+1, parsed.Path)
				fmt.Fprintln(file, parsed.Scheme+"://"+parsed.Host+parsed.Path)

				if parsed.RawQuery != "" {
					for key, vals := range parsed.Query() {
						fmt.Fprintf(term, "│  │  └─ param: %s=%s\n", key, vals[0])
					}
					fmt.Fprintln(file, parsed.Scheme+"://"+parsed.Host+parsed.Path+"?"+parsed.RawQuery)
				}

				if recurs && depr < depth {
					pars(l, recurs, depr+1, depth, term, file, visited, skipList)
				}
			}
		}
	}
}

func main() {
	targetURL := flag.String("u", "", "Target URL to crawl")
	recursive := flag.Bool("r", false, "Enable recursive crawling")
	maxDepth := flag.Int("rd", 0, "Maximum recursion depth")
	pentest := flag.Bool("ps", false, "Run pentest scan after crawl")
	skipFlag := flag.String("skip", "", "Comma-separated list of path patterns to skip (e.g. delete,remove,logout)")
	skipPhases := flag.String("skip-phase", "", "Comma-separated phases to skip (1=SQLi,2=NUCLEI,3=SQLMap,4=XSS) e.g. 2,4")
	flag.Parse()

	if *targetURL == "" {
		fmt.Println("ERROR: please provide URL with -u flag")
		fmt.Println("Usage: ./luska -u <URL> [-r] [-rd <depth>] [-ps] [-skip <patterns>] [-skip-phase <phases>]")
		fmt.Println("\nPhases:")
		fmt.Println("  1 = Quick SQLi Test")
		fmt.Println("  2 = NUCLEI Template Scan")
		fmt.Println("  3 = SQLMap Deep Scan")
		fmt.Println("  4 = Dalfox XSS Scan")
		return
	}

	var skipList []string
	if *skipFlag != "" {
		for _, s := range strings.Split(*skipFlag, ",") {
			skipList = append(skipList, strings.TrimSpace(s))
		}
	}

	os.MkdirAll("output", 0755)
	os.MkdirAll("Poutput", 0755)

	parsed, err := url.Parse(*targetURL)
	if err != nil {
		fmt.Printf("ERROR: Invalid URL: %v\n", err)
		return
	}

	date := time.Now().Format("2006-01-02_15-04-05")
	crawlPath := "output/" + parsed.Hostname() + "|" + date + ".txt"

	f, err := os.Create(crawlPath)
	if err != nil {
		fmt.Printf("ERROR: Cannot create file: %v\n", err)
		return
	}
	defer f.Close()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("[*] CRAWLING STARTED: %s\n", *targetURL)
	if len(skipList) > 0 {
		fmt.Printf("[*] SKIPPING PATTERNS: %s\n", strings.Join(skipList, ", "))
	}
	fmt.Println(strings.Repeat("=", 60))

	visited := make(map[string]bool)
	pars(*targetURL, *recursive, 0, *maxDepth, os.Stdout, f, visited, skipList)
	f.Sync()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("[+] CRAWL COMPLETE: %s\n", crawlPath)
	fmt.Println(strings.Repeat("=", 60))

	if *pentest {
		fmt.Println("\n[*] Starting pentest scan...")

		pentestArgs := []string{
			"-f", crawlPath,
			"-host", parsed.Hostname(),
			"-date", date,
		}

		if *skipPhases != "" {
			pentestArgs = append(pentestArgs, "-skip-phase", *skipPhases)
		}
		
		cmd := exec.Command("./pentest", pentestArgs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("[ERROR] Pentest failed: %v\n", err)
		}
	}
}
