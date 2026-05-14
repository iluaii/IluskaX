package modules

import (
	"sort"
	"testing"
)

func TestIDORSurfaceReasons(t *testing.T) {
	cases := []struct {
		raw    string
		want   []string
		wantNil bool
	}{
		{
			raw:  "https://app.example/api/v1/users/42/settings",
			want: []string{"numeric/uuid id after REST-like segment /users/"},
		},
		{
			raw: "https://app.example/orders/550e8400-e29b-41d4-a716-446655440000",
			want: []string{
				"path segment looks like UUID",
				"numeric/uuid id after REST-like segment /orders/",
			},
		},
		{
			raw:  "https://cdn.example/static/app.js",
			wantNil: true,
		},
		{
			raw:  "https://app.example/page?id=12345&ref=1",
			want: []string{"query id= with numeric value"},
		},
		{
			raw:  "https://app.example/view?account_id=abc",
			want: []string{"query param name suggests object reference: account_id"},
		},
		{
			raw:  "https://app.example/data?transaction_id=1",
			want: []string{"query param ends with _id: transaction_id"},
		},
		{
			raw:  "https://app.example/reports/12345678/summary",
			want: []string{"path segment is long numeric id"},
		},
	}
	for _, tc := range cases {
		got := idorSurfaceReasons(tc.raw)
		if tc.wantNil {
			if len(got) != 0 {
				t.Errorf("%q: want no reasons, got %v", tc.raw, got)
			}
			continue
		}
		sort.Strings(got)
		sort.Strings(tc.want)
		if len(got) != len(tc.want) {
			t.Errorf("%q: got %v want %v", tc.raw, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%q: got %v want %v", tc.raw, got, tc.want)
				break
			}
		}
	}
}
