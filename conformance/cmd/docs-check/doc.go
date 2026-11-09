package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Finding is one thing the check refuses, with the place and the remedy in plain words.
type Finding struct {
	File string
	Line int
	Msg  string
}

func (f Finding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("FAIL %s:%d — %s", f.File, f.Line, f.Msg)
	}
	return fmt.Sprintf("FAIL %s — %s", f.File, f.Msg)
}

// Block is one fenced code block of a document.
type Block struct {
	Line   int      // line of the opening fence, 1-based
	Info   []string // the words after the fence
	Script string
}

// Has reports whether the block's info string carries the token.
func (b Block) Has(token string) bool {
	for _, t := range b.Info {
		if t == token {
			return true
		}
	}
	return false
}

// Option returns the value of a `key=value` word of the info string.
func (b Block) Option(key string) string {
	for _, t := range b.Info {
		if v, ok := strings.CutPrefix(t, key+"="); ok {
			return v
		}
	}
	return ""
}

// Heading is a level-2 heading outside any fence.
type Heading struct {
	Line  int
	Title string
}

// Item is one line of prose or one bullet of a section.
type Item struct {
	Line   int
	Bullet bool
	Text   string // the bullet's text, continuation lines joined with a space
}

// Doc is a Markdown document reduced to what the check reads.
type Doc struct {
	Name     string
	Headings []Heading
	Blocks   []Block
	// Unclosed is the line of a fence opened and never closed, or 0. Its lines are not a block: nothing runs.
	Unclosed int
	// Sections maps a heading's title to the prose items under it, fences excluded.
	Sections map[string][]Item
}

var fenceRe = regexp.MustCompile("^(`{3,})\\s*(.*)$")

// ParseDoc reads a document. A line inside a fence is never a heading and never an item.
func ParseDoc(name string, data []byte) *Doc {
	d := &Doc{Name: name, Sections: map[string][]Item{}}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var (
		n       int
		fence   string
		cur     *Block
		current string
		items   []Item
	)
	flush := func() {
		if current != "" {
			d.Sections[current] = items
		}
		items = nil
	}
	for sc.Scan() {
		n++
		line := sc.Text()
		if fence != "" {
			if strings.HasPrefix(strings.TrimSpace(line), fence) && strings.TrimSpace(line) == fence {
				d.Blocks = append(d.Blocks, *cur)
				fence, cur = "", nil
				continue
			}
			cur.Script += line + "\n"
			continue
		}
		if m := fenceRe.FindStringSubmatch(line); m != nil {
			fence = m[1]
			cur = &Block{Line: n, Info: strings.Fields(m[2])}
			continue
		}
		if t, ok := strings.CutPrefix(line, "## "); ok {
			flush()
			current = strings.TrimSpace(t)
			d.Headings = append(d.Headings, Heading{Line: n, Title: current})
			continue
		}
		if current == "" || strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue // a deeper heading is structure, not a claim
		}
		if t, ok := strings.CutPrefix(line, "- "); ok {
			items = append(items, Item{Line: n, Bullet: true, Text: strings.TrimSpace(t)})
			continue
		}
		if len(items) > 0 && items[len(items)-1].Bullet && strings.HasPrefix(line, "  ") {
			items[len(items)-1].Text += " " + strings.TrimSpace(line)
			continue
		}
		items = append(items, Item{Line: n, Text: strings.TrimSpace(line)})
	}
	flush()
	if cur != nil {
		d.Unclosed = cur.Line
	}
	return d
}

// ReadDoc reads and parses a file.
func ReadDoc(path, name string) (*Doc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseDoc(name, data), nil
}
