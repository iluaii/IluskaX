package modules

import (
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"IluskaX/internal/ui"
)

var idorPathUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var idorRESTKeywords = map[string]struct{}{
	"user": {}, "users": {}, "account": {}, "accounts": {}, "order": {}, "orders": {},
	"invoice": {}, "invoices": {}, "document": {}, "documents": {}, "item": {}, "items": {},
	"message": {}, "messages": {}, "thread": {}, "threads": {}, "profile": {}, "profiles": {},
	"customer": {}, "customers": {}, "client": {}, "clients": {}, "ticket": {}, "tickets": {},
	"report": {}, "reports": {}, "file": {}, "files": {}, "download": {}, "project": {}, "projects": {},
	"org": {}, "orgs": {}, "organization": {}, "organizations": {}, "team": {}, "teams": {},
	"payment": {}, "payments": {}, "subscription": {}, "subscriptions": {}, "post": {}, "posts": {},
	"comment": {}, "comments": {}, "cart": {}, "checkout": {}, "receipt": {}, "receipts": {},
	"api": {}, "record": {}, "records": {}, "entity": {}, "entities": {}, "resource": {}, "resources": {},
}

var idorQueryNames = map[string]struct{}{
	"user_id": {}, "userid": {}, "user": {}, "uid": {}, "account_id": {}, "accountid": {},
	"order_id": {}, "orderid": {}, "invoice_id": {}, "invoiceid": {}, "doc_id": {}, "document_id": {},
	"file_id": {}, "fileid": {}, "customer_id": {}, "customerid": {}, "org_id": {}, "organization_id": {},
	"project_id": {}, "projectid": {}, "message_id": {}, "thread_id": {}, "session_id": {}, "token_id": {},
}

func IDORSurfaceScan(urls []string, w io.Writer, sb *ui.StatusBar, rc *ui.ReportCollector) {
	fmt.Fprintln(w, "┌─ [PHASE 12] IDOR SURFACE (STATIC, NO EXTRA HTTP)")
	fmt.Fprintln(w, "├─ Heuristic only: checks path segments and query names; does not substitute IDs or call alternate objects.")

	if len(urls) == 0 {
		fmt.Fprintln(w, "└─ No URLs loaded, skipping")
		return
	}

	if sb != nil {
		sb.SetPhase("IDOR", int64(len(urls)))
	}

	found := 0
	for i, raw := range urls {
		reasons := idorSurfaceReasons(raw)
		if len(reasons) == 0 {
			if sb != nil {
				sb.Tick(1)
			}
			continue
		}
		found++
		sort.Strings(reasons)
		detail := strings.Join(reasons, "; ")
		if sb != nil {
			sb.Log("├─ [%d/%d] %s\n", i+1, len(urls), ui.Truncate(raw, ui.MaxURLLen))
		} else {
			fmt.Fprintf(w, "├─ [%d/%d] %s\n", i+1, len(urls), raw)
		}
		fmt.Fprintf(w, "│  [IDOR?] %s\n", detail)
		if rc != nil {
			rc.AddFinding(ui.Finding{
				Type:     ui.VulnIDOR,
				Level:    ui.LevelInfo,
				URL:      raw,
				Payload:  strings.Join(reasons, ", "),
				Detail:   "static surface tag — verify authorization on cross-tenant/object access",
				Severity: "info",
			})
		}
		if sb != nil {
			sb.Tick(1)
		}
	}

	if found == 0 {
		fmt.Fprintln(w, "├─ Status: No IDOR-like URL patterns detected")
	} else {
		fmt.Fprintf(w, "├─ Tagged URLs: %d (review manually; not a vulnerability by itself)\n", found)
	}
	fmt.Fprintln(w, "└─ IDOR surface pass complete")
}

func idorSurfaceReasons(raw string) []string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if IsStaticAsset(u.Path) {
		return nil
	}

	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	decodedPath := u.Path
	if up, err := url.PathUnescape(u.Path); err == nil {
		decodedPath = up
	}
	segs := splitPathSegments(decodedPath)
	for i := 0; i < len(segs); i++ {
		seg := segs[i]
		if idorPathUUID.MatchString(seg) {
			add("path segment looks like UUID")
		}
		if len(seg) >= 8 && len(seg) <= 32 && isAllDigits(seg) {
			add("path segment is long numeric id")
		}
		if i > 0 {
			prev := strings.ToLower(segs[i-1])
			if _, ok := idorRESTKeywords[prev]; ok && isObjectIDToken(seg) {
				add("numeric/uuid id after REST-like segment /" + segs[i-1] + "/")
			}
		}
	}

	q := u.Query()
	for key, vals := range q {
		lk := strings.ToLower(strings.TrimSpace(key))
		if _, ok := idorQueryNames[lk]; ok {
			add("query param name suggests object reference: " + key)
			continue
		}
		if strings.HasSuffix(lk, "_id") && lk != "grid_id" {
			add("query param ends with _id: " + key)
			continue
		}
		if lk == "id" && len(vals) > 0 && isAllDigits(vals[0]) && len(vals[0]) >= 4 {
			add("query id= with numeric value")
		}
	}

	return out
}

func splitPathSegments(p string) []string {
	p = path.Clean("/" + p)
	if p == "/" || p == "." {
		return nil
	}
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isObjectIDToken(seg string) bool {
	if idorPathUUID.MatchString(seg) {
		return true
	}
	if isAllDigits(seg) && len(seg) >= 1 && len(seg) <= 6 {
		return true
	}
	return false
}
