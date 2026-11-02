package main

import (
	"regexp"
	"strings"
)

// A Statement is one sentence or table row of a draft that contains a BCP 14
// keyword.
type Statement struct {
	Line    int
	Level   string
	Text    string
	Section string // anchor of the innermost enclosing heading
	Path    []int  // lines of the enclosing headings, outermost first
}

// A Draft is a parsed pinned draft: its statements and its anchors.
type Draft struct {
	Lines      int
	Statements []Statement
	// Anchors maps a heading or figure anchor to where it is declared. The
	// first declaration of a repeated anchor is kept.
	Anchors map[string]Anchor
}

// An Anchor is declared on Line and names the section whose heading is on
// Section: the heading itself, or for a figure the section containing it.
type Anchor struct {
	Line, Section int
}

var (
	headingRE  = regexp.MustCompile(`^\.?(#{1,6})\s+(.*?)\s*(\{#([^}]+)\})?\s*$`)
	figureRE   = regexp.MustCompile(`^Figure:.*\{#([^}]+)\}\s*$`)
	listRE     = regexp.MustCompile(`^\s*([-*+]|\d+\.)\s+`)
	tableSepRE = regexp.MustCompile(`^\s*\|[\s:|-]+\|?\s*$`)
	keywordRE  = regexp.MustCompile(`\b(MUST NOT|MUST|REQUIRED|SHALL NOT|SHALL|SHOULD NOT|SHOULD|NOT RECOMMENDED|RECOMMENDED|MAY|OPTIONAL)\b`)
	slugDropRE = regexp.MustCompile(`[^a-z0-9 _-]`)
	spacesRE   = regexp.MustCompile(` +`)
)

// excludedSection names top-level sections whose keywords describe changes
// to the draft rather than state requirements.
const excludedSection = "Document History"

var levels = map[string]string{
	"MUST": "must", "MUST NOT": "must", "REQUIRED": "must", "SHALL": "must", "SHALL NOT": "must",
	"SHOULD": "should", "SHOULD NOT": "should", "RECOMMENDED": "should", "NOT RECOMMENDED": "should",
	"MAY": "may", "OPTIONAL": "may",
}
var rank = map[string]int{"must": 0, "should": 1, "may": 2}

// slug is the anchor of a heading that declares none: lower case, letters,
// digits, spaces, hyphens and underscores kept, runs of spaces made one hyphen.
func slug(title string) string {
	s := slugDropRE.ReplaceAllString(strings.ToLower(title), "")
	return spacesRE.ReplaceAllString(strings.TrimSpace(s), "-")
}

type unit struct {
	parts           []part
	section         string
	path            []int
	excluded, table bool
}
type part struct {
	line int
	text string
}

// ParseDraft reads a draft in mmark/kramdown markdown. Front matter, fenced
// code, HTML comments and directive lines are skipped. Paragraphs and list
// items are split into sentences; each table row is one unit.
func ParseDraft(src string) Draft {
	lines := strings.Split(src, "\n")
	d := Draft{Lines: len(lines), Anchors: map[string]Anchor{}}
	type heading struct {
		level, line   int
		anchor, title string
	}
	var stack []heading
	var units []unit
	var cur *unit
	front, fence, comment := false, false, false
	newUnit := func(parts ...part) unit {
		u := unit{parts: parts, path: make([]int, len(stack))}
		for i, h := range stack {
			u.path[i] = h.line
			u.section = h.anchor
		}
		u.excluded = len(stack) > 0 && strings.HasPrefix(stack[0].title, excludedSection)
		return u
	}
	innermost := func() int {
		if len(stack) == 0 {
			return 0
		}
		return stack[len(stack)-1].line
	}
	flush := func() {
		if cur != nil {
			units = append(units, *cur)
			cur = nil
		}
	}
	for i, raw := range lines {
		n := i + 1
		trim := strings.TrimSpace(raw)
		switch {
		case n == 1 && (trim == "%%%" || trim == "---"):
			front = true
			continue
		case front:
			if trim == "%%%" || trim == "---" || trim == "..." {
				front = false
			}
			continue
		case strings.HasPrefix(trim, "~~~") || strings.HasPrefix(trim, "```"):
			flush()
			fence = !fence
			continue
		case fence:
			continue
		case comment:
			if strings.Contains(trim, "-->") {
				comment = false
			}
			continue
		case strings.HasPrefix(trim, "<!--"):
			flush()
			comment = !strings.Contains(trim, "-->")
			continue
		}
		if m := headingRE.FindStringSubmatch(raw); m != nil {
			flush()
			level, anchor := len(m[1]), m[4]
			if anchor == "" {
				anchor = slug(m[2])
			}
			for len(stack) > 0 && stack[len(stack)-1].level >= level {
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, heading{level, n, anchor, m[2]})
			if _, dup := d.Anchors[anchor]; !dup {
				d.Anchors[anchor] = Anchor{Line: n, Section: n}
			}
			continue
		}
		if m := figureRE.FindStringSubmatch(trim); m != nil {
			flush()
			if _, dup := d.Anchors[m[1]]; !dup {
				d.Anchors[m[1]] = Anchor{Line: n, Section: innermost()}
			}
			continue
		}
		if trim == "" || strings.HasPrefix(trim, "{") {
			flush()
			continue
		}
		text := strings.TrimSpace(strings.TrimPrefix(trim, ">"))
		if strings.HasPrefix(text, "|") {
			flush()
			if !tableSepRE.MatchString(text) {
				u := newUnit(part{n, text})
				u.table = true
				units = append(units, u)
			}
			continue
		}
		if listRE.MatchString(raw) {
			flush()
		}
		if cur == nil {
			u := newUnit()
			cur = &u
		}
		cur.parts = append(cur.parts, part{n, text})
	}
	flush()
	for _, u := range units {
		if !u.excluded {
			d.Statements = append(d.Statements, u.statements()...)
		}
	}
	return d
}

// statements joins a unit's lines with single spaces, splits it into
// sentences (a table row stays whole) and keeps those with a keyword, each at
// the line it starts on. A sentence of at most two words, such as
// "REQUIRED.", joins the sentence before it.
func (u unit) statements() []Statement {
	var b strings.Builder
	starts := make([]int, len(u.parts)) // offset of each part in the joined text
	for i, p := range u.parts {
		if i > 0 {
			b.WriteByte(' ')
		}
		starts[i] = b.Len()
		b.WriteString(p.text)
	}
	text := b.String()
	lineAt := func(off int) int {
		line := u.parts[0].line
		for i, s := range starts {
			if s <= off {
				line = u.parts[i].line
			}
		}
		return line
	}
	spans := [][2]int{{0, len(text)}}
	if !u.table {
		spans = spans[:0]
		for _, span := range sentences(text) {
			if len(spans) > 0 && len(strings.Fields(text[span[0]:span[1]])) <= 2 {
				spans[len(spans)-1][1] = span[1]
				continue
			}
			spans = append(spans, span)
		}
	}
	var out []Statement
	for _, span := range spans {
		s := strings.Join(strings.Fields(text[span[0]:span[1]]), " ")
		level := ""
		for _, k := range keywordRE.FindAllString(s, -1) {
			if l := levels[k]; level == "" || rank[l] < rank[level] {
				level = l
			}
		}
		if level != "" {
			out = append(out, Statement{Line: lineAt(span[0]), Level: level, Text: s, Section: u.section, Path: u.path})
		}
	}
	return out
}

// sentences splits after '.', '!' or '?' (and any closing quote, bracket,
// backtick or emphasis) followed by whitespace and a capital letter or an
// opening quote, bracket, backtick or emphasis.
func sentences(text string) [][2]int {
	var spans [][2]int
	start := 0
	for i := 0; i < len(text); i++ {
		if c := text[i]; c != '.' && c != '!' && c != '?' {
			continue
		}
		j := i + 1
		for j < len(text) && strings.IndexByte(`)"'`+"`*_]", text[j]) >= 0 {
			j++
		}
		k := j
		for k < len(text) && text[k] == ' ' {
			k++
		}
		if k == j || k >= len(text) {
			continue
		}
		if c := text[k]; (c >= 'A' && c <= 'Z') || strings.IndexByte(`"(`+"`[*_", c) >= 0 {
			spans = append(spans, [2]int{start, j})
			start = k
			i = k - 1
		}
	}
	if start < len(text) {
		spans = append(spans, [2]int{start, len(text)})
	}
	return spans
}
