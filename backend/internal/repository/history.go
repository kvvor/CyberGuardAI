package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type HistoryFilter struct {
	Page, Size                  int
	Mode, Verdict, Search, Sort string
	From, To                    *time.Time
}

func ParseHistory(q url.Values) (HistoryFilter, error) {
	f := HistoryFilter{Page: 1, Size: 20, Mode: "live", Sort: "newest"}
	bad := fmt.Errorf("INVALID_FILTER")
	for k, dest := range map[string]*int{"page": &f.Page, "page_size": &f.Size} {
		if q.Get(k) != "" {
			n, e := strconv.Atoi(q.Get(k))
			if e != nil {
				return f, bad
			}
			*dest = n
		}
	}
	if f.Page < 1 || f.Page > 100000 || f.Size < 1 || f.Size > 100 {
		return f, bad
	}
	if q.Get("mode") != "" {
		f.Mode = q.Get("mode")
	}
	if f.Mode != "live" && f.Mode != "demo" {
		return f, bad
	}
	f.Verdict = q.Get("verdict")
	switch f.Verdict {
	case "", "legitimate", "suspicious", "phishing", "inconclusive":
	default:
		return f, bad
	}
	if q.Get("sort") != "" {
		f.Sort = q.Get("sort")
	}
	switch f.Sort {
	case "newest", "oldest", "risk_desc", "risk_asc":
	default:
		return f, bad
	}
	f.Search = q.Get("search")
	if len(f.Search) > 256 {
		return f, bad
	}
	for k, dest := range map[string]**time.Time{"date_from": &f.From, "date_to": &f.To} {
		if raw := q.Get(k); raw != "" {
			d, e := time.Parse(time.RFC3339, raw)
			if e != nil {
				d, e = time.Parse("2006-01-02", raw)
				if e == nil && k == "date_to" {
					d = d.AddDate(0, 0, 1)
				}
			}
			if e != nil {
				return f, bad
			}
			*dest = &d
		}
	}
	if f.From != nil && f.To != nil && !f.From.Before(*f.To) {
		return f, bad
	}
	return f, nil
}
func History(ctx context.Context, db *pgxpool.Pool, owner string, f HistoryFilter) ([]json.RawMessage, int, error) {
	order := map[string]string{"newest": "created_at DESC,id", "oldest": "created_at ASC,id", "risk_desc": "risk_score DESC,created_at DESC,id", "risk_asc": "risk_score ASC,created_at DESC,id"}[f.Sort]
	if order == "" {
		return nil, 0, fmt.Errorf("invalid sort")
	}
	search := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(f.Search)
	where := ` FROM analyses WHERE user_id=$1 AND mode=$2 AND ($3='' OR verdict=$3) AND (subject ILIKE $4 OR sender ILIKE $4) AND ($5::timestamptz IS NULL OR created_at >= $5) AND ($6::timestamptz IS NULL OR created_at < $6)`
	args := []any{owner, f.Mode, f.Verdict, "%" + search + "%", f.From, f.To}
	var total int
	if e := db.QueryRow(ctx, "SELECT count(*)"+where, args...).Scan(&total); e != nil {
		return nil, 0, e
	}
	args = append(args, f.Size, (f.Page-1)*f.Size)
	rows, e := db.Query(ctx, "SELECT report"+where+" ORDER BY "+order+" LIMIT $7 OFFSET $8", args...)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	items := []json.RawMessage{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return nil, 0, e
		}
		if !json.Valid(b) {
			return nil, 0, fmt.Errorf("invalid stored report")
		}
		items = append(items, json.RawMessage(b))
	}
	return items, total, rows.Err()
}
