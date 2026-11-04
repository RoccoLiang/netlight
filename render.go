package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

type renderMode struct {
	Emoji, Color, Detail bool
}

var (
	emojiMark  = [...]string{"🟢", "🟡", "🔴", "⚪"}
	plainMark  = [...]string{"[正常]", "[注意]", "[故障]", "[略過]"}
	statusWord = [...]string{"正常", "注意", "故障", "略過"}
	ansiColor  = [...]string{"\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[90m"}
)

const ansiReset = "\x1b[0m"

// padName：燈名一律補到 4 個全形字寬，再接一個全形空白
func padName(s string) string {
	return s + strings.Repeat("　", 5-utf8.RuneCountInString(s))
}

func render(w io.Writer, r Report, osName string, now time.Time, m renderMode) {
	fmt.Fprintf(w, "網路紅綠燈 netlight v%s · %s · %s\n", version, osName, now.Format("2006-01-02 15:04"))
	for _, l := range r.Lights {
		mark := plainMark[l.Status]
		if m.Emoji {
			mark = emojiMark[l.Status] + " " + statusWord[l.Status]
		} else if m.Color {
			mark = ansiColor[l.Status] + mark + ansiReset
		}
		fmt.Fprintf(w, "%s %s%s\n", mark, padName(l.Name), l.Summary)
		if m.Detail {
			for _, e := range l.Evidence {
				fmt.Fprintf(w, "      · %s\n", e)
			}
		}
	}
	renderVerdict(w, r.Verdict)
}

// renderVerdict：輸出結論、建議、聯絡
func renderVerdict(w io.Writer, v Verdict) {
	fmt.Fprintf(w, "結論：%s\n", v.Text)
	fmt.Fprintf(w, "建議：%s\n", v.Action)
	if v.Contact != "" {
		if v.Org != "" {
			fmt.Fprintf(w, "聯絡（%s）：%s\n", v.Org, v.Contact)
		} else {
			fmt.Fprintf(w, "聯絡：%s\n", v.Contact)
		}
	}
}

type jsonReport struct {
	Version string `json:"version"`
	Time    string `json:"time"`
	OS      string `json:"os"`
	Report
	Facts Facts `json:"facts"`
}

func renderJSON(w io.Writer, r Report, f Facts, now time.Time) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(jsonReport{version, now.Format(time.RFC3339), f.Local.OS, r, f})
}
