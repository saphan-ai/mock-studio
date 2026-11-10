package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The public documents and the sections each must carry, in order. The lists are the level-2 headings the published
// documents carry (`grep -nE '^## ' README.md SECURITY.md CONTRIBUTING.md`); the check follows the documents. A
// section may be followed by others, but these appear in this order.
var (
	readmeSections = []string{
		"Try it first (5 minutes)",
		"The problem",
		"What this repository gives you today",
		"What is in this repository",
		"What it will be",
		"How it will be built",
		"Honest limits",
		"Write your own mock",
		"Development",
		"Licence",
	}
	securitySections = []string{
		"Reporting a vulnerability",
		"What is in scope",
		"What is not in scope",
		"Supported versions",
	}
	contributingSections = []string{
		"Before you start",
		"Adding a mock",
		"Tests",
		"Wording",
		"Commits and pull requests",
	}
)

const (
	// measuredSection is not required: the README carries no such section today. When a document has one, every
	// line under it must carry a command that prints its number.
	measuredSection = "What is measured"
	limitsSection   = "Honest limits"
	// contributingRunSection is where CONTRIBUTING.md tells a contributor how to run the suite.
	contributingRunSection = "Adding a mock"
	suiteCommand           = "mocks-conformance"
)

// retiredClaims are sentences the documents once made and the code does not hold. A document that says one again is
// refused, naming what is true. The match ignores case and the breaks between lines.
var retiredClaims = []struct{ phrase, truth string }{
	{"each protection below is a check in the suite",
		"the suite checks only the protections that name check ids; the others are spec or contribution rules, or what some mocks do"},
	{"listen on loopback only",
		"only the scim and mcp mocks refuse a host that is not loopback; the other five bind the host they are given"},
	{"the mocks listen on loopback,",
		"only the scim and mcp mocks refuse a host that is not loopback; the other five bind the host they are given"},
	{"everything uses loopback only",
		"the commands use 127.0.0.1; that is not a property the mocks enforce"},
}

var requiredFiles = []string{"README.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE"}

var (
	codeSpanRe = regexp.MustCompile("`([^`]+)`")
	dateRe     = regexp.MustCompile(`\b20\d\d-[01]\d-[0-3]\d\b`)
	leadNumRe  = regexp.MustCompile(`^(\d+)\b`)
	ipv4Re     = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
	hexRunRe   = regexp.MustCompile(`[0-9A-Fa-f:]{2,}`)
)

// StaticCheck reads the documents under root and returns what is wrong with their shape.
// It starts no process and opens no socket.
func StaticCheck(root string) []Finding {
	var out []Finding
	docs := map[string]*Doc{}
	for _, f := range requiredFiles {
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			out = append(out, Finding{File: f, Msg: fmt.Sprintf("the file does not exist; write %s at the repository root", f)})
			continue
		}
		if f == "LICENSE" {
			out = append(out, checkLicense(f, string(data))...)
			continue
		}
		docs[f] = ParseDoc(f, data)
		if u := docs[f].Unclosed; u > 0 {
			out = append(out, Finding{File: f, Line: u, Msg: "the fence opened here is never closed; close it with the same number of backticks, or every block after it is lost"})
		}
		out = append(out, checkIPs(f, string(data))...)
		out = append(out, checkRetired(f, string(data))...)
	}
	for _, p := range []struct {
		file string
		want []string
	}{{"README.md", readmeSections}, {"SECURITY.md", securitySections}, {"CONTRIBUTING.md", contributingSections}} {
		if d := docs[p.file]; d != nil {
			out = append(out, checkSections(d, p.want)...)
		}
	}
	if d := docs["README.md"]; d != nil {
		out = append(out, checkMeasured(d)...)
		out = append(out, checkLimits(d)...)
		if len(d.Blocks) == 0 {
			out = append(out, Finding{File: d.Name, Msg: "no fenced block; a stranger's path through the README must be commands in a block"})
		}
	}
	if d := docs["CONTRIBUTING.md"]; d != nil && !tellsHowToRunSuite(d) {
		out = append(out, Finding{File: d.Name, Msg: fmt.Sprintf("section %q does not name the suite command in backticks (`... %s ...`); how to run the suite must be a command", contributingRunSection, suiteCommand)})
	}
	return out
}

// tellsHowToRunSuite reports whether the contributing section carries the suite command as an inline code span.
func tellsHowToRunSuite(d *Doc) bool {
	for _, it := range d.Sections[contributingRunSection] {
		for _, m := range codeSpanRe.FindAllStringSubmatch(it.Text, -1) {
			if strings.Contains(m[1], suiteCommand) {
				return true
			}
		}
	}
	return false
}

func checkLicense(name, text string) []Finding {
	if !strings.Contains(text, "Apache License") || !strings.Contains(text, "Version 2.0, January 2004") ||
		!strings.Contains(text, "END OF TERMS AND CONDITIONS") {
		return []Finding{{File: name, Msg: "the file is not the full text of the Apache License, Version 2.0; replace it with the complete text"}}
	}
	return nil
}

// checkSections names every missing section, and when all are present but out of order names the order.
func checkSections(d *Doc, want []string) []Finding {
	pos := map[string]int{}
	for _, h := range d.Headings {
		if _, seen := pos[h.Title]; !seen {
			pos[h.Title] = h.Line
		}
	}
	var out []Finding
	for _, w := range want {
		if _, ok := pos[w]; !ok {
			out = append(out, Finding{File: d.Name, Msg: fmt.Sprintf("section %q is missing; add `## %s`", w, w)})
		}
	}
	if len(out) > 0 {
		return out
	}
	for i := 1; i < len(want); i++ {
		if pos[want[i]] < pos[want[i-1]] {
			out = append(out, Finding{File: d.Name, Line: pos[want[i]], Msg: fmt.Sprintf(
				"section %q (line %d) comes before %q (line %d); the order is: %s",
				want[i], pos[want[i]], want[i-1], pos[want[i-1]], strings.Join(want, " · "))})
		}
	}
	return out
}

// MeasuredCommand returns the command of a measured bullet: its last inline code span.
func MeasuredCommand(text string) (string, bool) {
	m := codeSpanRe.FindAllStringSubmatch(text, -1)
	if len(m) == 0 {
		return "", false
	}
	return m[len(m)-1][1], true
}

// checkMeasured asserts that every line under "What is measured" is a bullet that carries a command.
func checkMeasured(d *Doc) []Finding {
	items, ok := d.Sections[measuredSection]
	if !ok {
		return nil // the missing section is named by checkSections
	}
	var out []Finding
	if len(items) == 0 {
		out = append(out, Finding{File: d.Name, Msg: fmt.Sprintf("section %q holds no claim; list each measured number with its command", measuredSection)})
	}
	for _, it := range items {
		if !it.Bullet {
			out = append(out, Finding{File: d.Name, Line: it.Line, Msg: fmt.Sprintf("a line under %q that is not a bullet carries no command: %q", measuredSection, clip(it.Text))})
			continue
		}
		if _, ok := MeasuredCommand(it.Text); !ok {
			out = append(out, Finding{File: d.Name, Line: it.Line, Msg: fmt.Sprintf("the measured claim %q carries no command; end the line with the command in backticks", clip(it.Text))})
			continue
		}
		if !leadNumRe.MatchString(it.Text) {
			out = append(out, Finding{File: d.Name, Line: it.Line, Msg: fmt.Sprintf("the measured claim %q does not start with the number its command prints, so nothing compares them; start the line with the number", clip(it.Text))})
		}
	}
	return out
}

// checkLimits asserts that every limit is dated.
func checkLimits(d *Doc) []Finding {
	items, ok := d.Sections[limitsSection]
	if !ok {
		return nil
	}
	var out []Finding
	if len(items) == 0 {
		out = append(out, Finding{File: d.Name, Msg: fmt.Sprintf("section %q lists no limit", limitsSection)})
	}
	for _, it := range items {
		if !dateRe.MatchString(it.Text) {
			out = append(out, Finding{File: d.Name, Line: it.Line, Msg: fmt.Sprintf("the limit %q has no date; a limit is a measurement, write the day it was measured as YYYY-MM-DD", clip(it.Text))})
		}
	}
	return out
}

// checkIPs refuses an IPv4 address that is neither loopback nor a reserved documentation address (RFC 5737), and an
// IPv6 address that is neither ::1 nor in the documentation range 2001:db8::/32 (RFC 3849).
func checkIPs(name, text string) []Finding {
	var out []Finding
	for i, line := range strings.Split(text, "\n") {
		for _, m := range hexRunRe.FindAllString(line, -1) {
			if strings.Count(m, ":") < 2 || net.ParseIP(m) == nil || reservedIPv6(m) {
				continue
			}
			out = append(out, Finding{File: name, Line: i + 1, Msg: fmt.Sprintf("the address %s is neither loopback (::1) nor reserved for documentation (2001:db8::/32); remove it", m)})
		}
		for _, m := range ipv4Re.FindAllStringSubmatch(line, -1) {
			if reservedIPv4(m[0]) {
				continue
			}
			out = append(out, Finding{File: name, Line: i + 1, Msg: fmt.Sprintf("the address %s is neither loopback, 0.0.0.0 nor reserved for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); remove it", m[0])})
		}
	}
	return out
}

func reservedIPv4(s string) bool {
	return s == "0.0.0.0" || strings.HasPrefix(s, "127.") || strings.HasPrefix(s, "192.0.2.") ||
		strings.HasPrefix(s, "198.51.100.") || strings.HasPrefix(s, "203.0.113.")
}

// checkRetired refuses a sentence from retiredClaims, naming the line it starts on.
func checkRetired(name, text string) []Finding {
	flat := strings.ToLower(strings.Join(strings.Fields(text), " "))
	var out []Finding
	for _, c := range retiredClaims {
		if !strings.Contains(flat, c.phrase) {
			continue
		}
		// The line is the first one that holds the phrase's first two words; 0 when a break splits them.
		line, lead := 0, strings.Join(strings.Fields(c.phrase)[:2], " ")
		for n, l := range strings.Split(strings.ToLower(text), "\n") {
			if strings.Contains(strings.Join(strings.Fields(l), " "), lead) {
				line = n + 1
				break
			}
		}
		out = append(out, Finding{File: name, Line: line, Msg: fmt.Sprintf("the claim %q is one the code does not hold; %s", c.phrase, c.truth)})
	}
	return out
}

func reservedIPv6(s string) bool {
	s = strings.ToLower(s)
	return s == "::" || s == "::1" || strings.HasPrefix(s, "2001:db8:") || strings.HasPrefix(s, "2001:0db8:")
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}
