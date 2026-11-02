package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Keyword is an EDN keyword, without its colon.
type Keyword string

// Render writes the map as EDN: one top-level key per line and one element
// of each top-level vector per line.
func Render(m Map) []byte {
	var b strings.Builder
	b.WriteString("{:version " + strconv.Itoa(m.Version) + "\n")
	b.WriteString(" :suite-sha256 " + str(m.SuiteSHA256) + "\n")
	b.WriteString(" :reports-source " + str(m.ReportsSource) + "\n")
	vector := func(name string, n int, item func(int) string) {
		b.WriteString(" :" + name + "\n [")
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString("\n  ")
			}
			b.WriteString(item(i))
		}
		b.WriteString("]")
	}
	vector("drafts", len(m.Drafts), func(i int) string {
		d := m.Drafts[i]
		return "{:id " + str(d.ID) + " :file " + str(d.File) + " :commit " + str(d.Commit) + " :sha256 " + str(d.SHA256) + " :lines " + strconv.Itoa(d.Lines) + "}"
	})
	b.WriteString("\n")
	vector("reports", len(m.Reports), func(i int) string {
		r := m.Reports[i]
		return "{:role " + str(r.Role) + " :library " + str(r.Library) + " :revision " + str(r.Revision) + " :execution " + kw(r.Execution) + " :suite-sha256 " + str(r.SuiteSHA256) + "}"
	})
	b.WriteString("\n")
	vector("scenarios", len(m.Scenarios), func(i int) string {
		s := m.Scenarios[i]
		return "{:id " + str(s.ID) + " :role " + str(s.Role) + " :file " + str(s.File) + "}"
	})
	b.WriteString("\n")
	vector("suite-clauses", len(m.SuiteClauses), func(i int) string {
		c := m.SuiteClauses[i]
		line := "nil"
		if c.AnchorLine > 0 {
			line = strconv.Itoa(c.AnchorLine)
		}
		return "{:id " + str(c.ID) + " :draft " + str(c.Draft) + " :anchor " + str(c.Anchor) + " :anchor-line " + line +
			" :role " + str(c.Role) + " :scope " + kw(c.Scope) + " :linked " + strconv.Itoa(c.Linked) +
			" :scenarios " + strs(c.Scenarios) + statusFields(c.Status, c.Reason) + "}"
	})
	b.WriteString("\n")
	vector("clauses", len(m.Clauses), func(i int) string {
		e := m.Clauses[i]
		return "{:id " + str(e.ID) + " :draft " + str(e.Draft) + " :line " + strconv.Itoa(e.Line) + " :level " + kw(e.Level) +
			" :section " + str(e.Section) + " :text " + str(e.Text) + " :suite-clauses " + strs(e.SuiteClauses) +
			" :scenarios " + strs(e.Scenarios) + statusFields(e.Status, e.Reason) + "}"
	})
	b.WriteString("}\n")
	return []byte(b.String())
}

// statusFields renders :status and :reason, each only when nonempty.
func statusFields(status, reason map[string]string) string {
	out := ""
	if len(status) > 0 {
		out += " :status " + kwMap(status, kw)
	}
	if len(reason) > 0 {
		out += " :reason " + kwMap(reason, str)
	}
	return out
}

func kwMap(m map[string]string, val func(string) string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = kw(k) + " " + val(m[k])
	}
	return "{" + strings.Join(parts, " ") + "}"
}

func kw(s string) string { return ":" + s }

func strs(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = str(s)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func str(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ParseEDN reads the subset Render writes: maps, vectors, strings, keywords,
// integers, nil, true and false. Maps become map[any]any keyed by Keyword or
// string; vectors []any; integers int.
func ParseEDN(src string) (any, error) {
	p := &ednParser{src: src}
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.space()
	if p.pos != len(p.src) {
		return nil, p.errorf("trailing data")
	}
	return v, nil
}

type ednParser struct {
	src string
	pos int
}

func (p *ednParser) errorf(format string, a ...any) error {
	line := 1 + strings.Count(p.src[:p.pos], "\n")
	return fmt.Errorf("edn line %d: %s", line, fmt.Sprintf(format, a...))
}

func (p *ednParser) space() {
	for p.pos < len(p.src) {
		switch c := p.src[p.pos]; {
		case c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == ',':
			p.pos++
		case c == ';':
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		default:
			return
		}
	}
}

func (p *ednParser) value() (any, error) {
	p.space()
	if p.pos >= len(p.src) {
		return nil, p.errorf("unexpected end")
	}
	switch c := p.src[p.pos]; {
	case c == '{':
		p.pos++
		m := map[any]any{}
		for {
			p.space()
			if p.pos < len(p.src) && p.src[p.pos] == '}' {
				p.pos++
				return m, nil
			}
			k, err := p.value()
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case Keyword, string:
			default:
				return nil, p.errorf("map key %v is not a keyword or string", k)
			}
			if _, dup := m[k]; dup {
				return nil, p.errorf("duplicate key %v", k)
			}
			if m[k], err = p.value(); err != nil {
				return nil, err
			}
		}
	case c == '[':
		p.pos++
		v := []any{}
		for {
			p.space()
			if p.pos < len(p.src) && p.src[p.pos] == ']' {
				p.pos++
				return v, nil
			}
			x, err := p.value()
			if err != nil {
				return nil, err
			}
			v = append(v, x)
		}
	case c == '"':
		return p.string()
	case c == ':':
		p.pos++
		return Keyword(p.token()), nil
	default:
		t := p.token()
		switch t {
		case "nil":
			return nil, nil
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		n, err := strconv.Atoi(t)
		if err != nil {
			return nil, p.errorf("unsupported token %q", t)
		}
		return n, nil
	}
}

func (p *ednParser) token() string {
	start := p.pos
	for p.pos < len(p.src) && !strings.ContainsRune(" \n\t\r,{}[]\";", rune(p.src[p.pos])) {
		p.pos++
	}
	return p.src[start:p.pos]
}

func (p *ednParser) string() (string, error) {
	p.pos++
	var b strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch c {
		case '"':
			p.pos++
			return b.String(), nil
		case '\\':
			if p.pos+1 >= len(p.src) {
				return "", p.errorf("unterminated escape")
			}
			e := p.src[p.pos+1]
			p.pos += 2
			switch e {
			case '"', '\\':
				b.WriteByte(e)
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'u':
				if p.pos+4 > len(p.src) {
					return "", p.errorf("short \\u escape")
				}
				r, err := strconv.ParseUint(p.src[p.pos:p.pos+4], 16, 32)
				if err != nil {
					return "", p.errorf("bad \\u escape")
				}
				b.WriteRune(rune(r))
				p.pos += 4
			default:
				return "", p.errorf("unsupported escape \\%c", e)
			}
		default:
			r, size := utf8.DecodeRuneInString(p.src[p.pos:])
			b.WriteRune(r)
			p.pos += size
		}
	}
	return "", p.errorf("unterminated string")
}
