package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// repoRoot is the repository root: this directory is conformance/cmd/docs-check.
const repoRoot = "../../.."

// copyDocs copies the public documents into a fresh directory and returns it.
func copyDocs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range requiredFiles {
		data, err := os.ReadFile(filepath.Join(repoRoot, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mutate(t *testing.T, dir, file string, f func(string) string) {
	t.Helper()
	p := filepath.Join(dir, file)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	out := f(string(data))
	if out == string(data) {
		t.Fatalf("the mutation of %s changed nothing; the control would prove nothing", file)
	}
	if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
}

func messages(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.String() + "\n")
	}
	return b.String()
}

func wantFinding(t *testing.T, fs []Finding, parts ...string) {
	t.Helper()
	got := messages(fs)
	for _, p := range parts {
		if !strings.Contains(got, p) {
			t.Fatalf("the findings do not contain %q:\n%s", p, got)
		}
	}
}

// The repository's own documents are clean.
func TestRepositoryDocumentsAreClean(t *testing.T) {
	if fs := StaticCheck(repoRoot); len(fs) != 0 {
		t.Fatalf("the documents are not clean:\n%s", messages(fs))
	}
}

// Negative control: the field mutated is the one the rule guards.
func TestMissingFilesAreNamed(t *testing.T) {
	fs := StaticCheck(t.TempDir())
	wantFinding(t, fs, "README.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE")
	if len(fs) != len(requiredFiles) {
		t.Fatalf("want one finding per missing file, got:\n%s", messages(fs))
	}
}

func TestRemovedSectionIsNamed(t *testing.T) {
	dir := copyDocs(t)
	mutate(t, dir, "README.md", func(s string) string { return strings.Replace(s, "## The problem\n", "", 1) })
	wantFinding(t, StaticCheck(dir), `section "The problem" is missing`)
}

func TestSwappedSectionsNameTheOrder(t *testing.T) {
	dir := copyDocs(t)
	mutate(t, dir, "README.md", func(s string) string {
		a := strings.Index(s, "## The problem")
		b := strings.Index(s, "## How it works")
		c := strings.Index(s, "## See a real example")
		return s[:a] + s[b:c] + s[a:b] + s[c:]
	})
	wantFinding(t, StaticCheck(dir), `section "How it works"`, `comes before "The problem"`, "the order is: What it is")
}

func TestMeasuredLineWithoutCommandIsNamedByLine(t *testing.T) {
	dir := copyDocs(t)
	var line int
	mutate(t, dir, "README.md", func(s string) string {
		const cmd = " `ls -d mocks/*/ | wc -l`"
		i := strings.Index(s, cmd)
		line = strings.Count(s[:i], "\n") + 1
		return strings.Replace(s, cmd, "", 1)
	})
	fs := StaticCheck(dir)
	wantFinding(t, fs, "README.md:"+itoa(line), "carries no command", "7 free mocks")
	if len(fs) != 1 {
		t.Fatalf("exactly the one line is named, got:\n%s", messages(fs))
	}
}

func TestProseUnderMeasuredIsRefused(t *testing.T) {
	dir := copyDocs(t)
	mutate(t, dir, "README.md", func(s string) string {
		return strings.Replace(s, "## What is measured\n\n", "## What is measured\n\nAll of this was measured.\n\n", 1)
	})
	wantFinding(t, StaticCheck(dir), "not a bullet carries no command", "All of this was measured.")
}

func TestUndatedLimitIsNamed(t *testing.T) {
	dir := copyDocs(t)
	mutate(t, dir, "README.md", func(s string) string {
		return strings.Replace(s, "- 2026-10-31: only the `scim`", "- only the `scim`", 1)
	})
	wantFinding(t, StaticCheck(dir), "has no date", "only the `scim`")
}

func TestForeignAddressIsNamed(t *testing.T) {
	dir := copyDocs(t)
	mutate(t, dir, "CONTRIBUTING.md", func(s string) string { return s + "\nThe host is 10.1." + "2.3.\n" })
	wantFinding(t, StaticCheck(dir), "CONTRIBUTING.md", "10.1."+"2.3")
	if fs := checkIPs("x", "127.0.0.1 192.0.2.7 198.51.100.1 203.0.113.9"); len(fs) != 0 {
		t.Fatalf("loopback and documentation ranges are allowed: %v", fs)
	}
}

func TestTruncatedLicenseIsNamed(t *testing.T) {
	dir := copyDocs(t)
	mutate(t, dir, "LICENSE", func(s string) string { return s[:len(s)/2] })
	wantFinding(t, StaticCheck(dir), "LICENSE", "not the full text of the Apache License")
}

func TestSecurityAndContributingSectionsAreHeld(t *testing.T) {
	dir := copyDocs(t)
	mutate(t, dir, "SECURITY.md", func(s string) string { return strings.Replace(s, "## What is still being checked", "## Later", 1) })
	mutate(t, dir, "CONTRIBUTING.md", func(s string) string { return strings.Replace(s, "## The clean-room rule", "## Rules", 1) })
	wantFinding(t, StaticCheck(dir), `"What is still being checked" is missing`, `"The clean-room rule" is missing`)
}

// The runner: a measured number must be what its command prints.
func TestMeasuredNumberMustMatchItsCommand(t *testing.T) {
	var out bytes.Buffer
	o := Options{Timeout: time.Minute, Out: &out}
	run := func(text string) Outcome {
		var res Outcome
		runDoc(context.Background(), t.TempDir(), ParseDoc("README.md", []byte(text)), true, o, &res)
		return res
	}
	head := "## What is measured\n\n"
	if r := run(head + "- 3 things — `echo 3`\n"); r.Pass != 1 || r.Fail != 0 {
		t.Fatalf("a true number passes: %+v\n%s", r, out.String())
	}
	r := run(head + "- 4 things — `echo 3`\n")
	if r.Fail != 1 || !strings.Contains(messages(r.Findings), "states 4 but the command prints \"3\"") {
		t.Fatalf("a wrong number is named: %+v\n%s", r, out.String())
	}
	if r := run(head + "- 3 things — `exit 7`\n"); r.Fail != 1 {
		t.Fatalf("a failing command fails: %+v", r)
	}
}

// A command that needs a socket is UNRUN, never PASS, where the host forbids one.
func TestSocketCommandIsUnrunWhereLoopbackIsDenied(t *testing.T) {
	var out bytes.Buffer
	o := Options{Timeout: time.Minute, Out: &out}
	var res Outcome
	doc := "```sh command net\ntrue\n```\n\n```sh command\ntrue\n```\n\n```sh\nexit 1\n```\n"
	runDoc(context.Background(), t.TempDir(), ParseDoc("CONTRIBUTING.md", []byte(doc)), false, o, &res)
	if res.Unrun != 1 || res.Pass != 1 || res.Fail != 0 {
		t.Fatalf("want 1 UNRUN, 1 PASS (an unmarked block is shown, never run), got %+v\n%s", res, out.String())
	}
	if !strings.Contains(out.String(), "UNRUN CONTRIBUTING.md:1 — "+loopbackDenied) {
		t.Fatalf("the UNRUN line carries the exact text:\n%s", out.String())
	}
}

func TestFencedLinesAreNeverHeadingsOrItems(t *testing.T) {
	d := ParseDoc("x.md", []byte("## A\n\n```\n## B\n- not an item\n```\n- real\n"))
	if len(d.Headings) != 1 || len(d.Sections["A"]) != 1 || d.Sections["A"][0].Text != "real" {
		t.Fatalf("a fence hides its lines: %+v", d)
	}
}

// The exit code: a failure is 1 even beside an UNRUN, an UNRUN alone is 4 and never 0, and only a clean run is 0.
func TestSummaryExitCodes(t *testing.T) {
	for _, c := range []struct {
		fail, pass, unrun, want int
	}{{0, 5, 0, 0}, {1, 5, 0, 1}, {0, 5, 1, 4}, {1, 5, 1, 1}, {0, 0, 0, 0}} {
		var out bytes.Buffer
		if got := summary(&out, c.fail, c.pass, c.unrun); got != c.want {
			t.Fatalf("summary(fail=%d pass=%d unrun=%d) = %d, want %d", c.fail, c.pass, c.unrun, got, c.want)
		}
		if !strings.Contains(out.String(), "SUMMARY "+itoa(c.fail)+" failed, "+itoa(c.pass)+" commands passed, "+itoa(c.unrun)+" UNRUN") {
			t.Fatalf("the SUMMARY line carries the three counts: %q", out.String())
		}
	}
}

// A requirement the host does not meet, or one the check does not know, makes the block UNRUN with the reason, never a pass.
func TestUnmetRequirementIsUnrun(t *testing.T) {
	if why := unmet("python9"); !strings.Contains(why, "unknown requirement python9") {
		t.Fatalf("an unknown requirement is named: %q", why)
	}
	if why := unmet("python9,venv"); !strings.Contains(why, "unknown requirement python9") {
		t.Fatalf("the first unmet requirement of a list is named: %q", why)
	}
	var out bytes.Buffer
	var res Outcome
	doc := "```sh command needs=python9\nexit 1\n```\n"
	runDoc(context.Background(), t.TempDir(), ParseDoc("CONTRIBUTING.md", []byte(doc)), true, Options{Timeout: time.Minute, Out: &out}, &res)
	if res.Unrun != 1 || res.Pass != 0 || res.Fail != 0 {
		t.Fatalf("want 1 UNRUN, got %+v\n%s", res, out.String())
	}
	if !strings.Contains(out.String(), "UNRUN CONTRIBUTING.md:1 — needs python9: unknown requirement python9") {
		t.Fatalf("the UNRUN line carries the reason:\n%s", out.String())
	}
}

// Public wording: the UNRUN text names the host, not the place the tool was built.
func TestUnrunTextIsPublicWording(t *testing.T) {
	if !strings.Contains(loopbackDenied, "on this host") || strings.Contains(loopbackDenied, "seat") {
		t.Fatalf("loopbackDenied = %q", loopbackDenied)
	}
}

// A measured bullet that does not start with a number compares nothing, so it is a failure, both before and while running.
func TestMeasuredBulletWithoutLeadingNumberFails(t *testing.T) {
	dir := copyDocs(t)
	mutate(t, dir, "README.md", func(s string) string { return strings.Replace(s, "- 7 free mocks:", "- seven free mocks:", 1) })
	wantFinding(t, StaticCheck(dir), "does not start with the number its command prints", "seven free mocks")

	var out bytes.Buffer
	var res Outcome
	doc := "## What is measured\n\n- seven things — `echo 7`\n"
	runDoc(context.Background(), t.TempDir(), ParseDoc("README.md", []byte(doc)), true, Options{Timeout: time.Minute, Out: &out}, &res)
	if res.Fail != 1 || res.Pass != 0 || !strings.Contains(messages(res.Findings), "does not start with the number") {
		t.Fatalf("a line without its number fails: %+v\n%s", res, out.String())
	}
}

// A fence that is opened and never closed hides its block from the runner, so it is named.
func TestUnclosedFenceIsNamed(t *testing.T) {
	d := ParseDoc("x.md", []byte("text\n\n```sh command\ntrue\n"))
	if d.Unclosed != 3 || len(d.Blocks) != 0 {
		t.Fatalf("the open fence is recorded at line 3 and is no block: %+v", d)
	}
	if d := ParseDoc("x.md", []byte("```sh\ntrue\n```\n")); d.Unclosed != 0 {
		t.Fatalf("a closed fence is not reported: %+v", d)
	}
	dir := copyDocs(t)
	var line int
	mutate(t, dir, "CONTRIBUTING.md", func(s string) string {
		line = strings.Count(s, "\n") + 2
		return s + "\n```sh command\ntrue\n"
	})
	wantFinding(t, StaticCheck(dir), "CONTRIBUTING.md:"+itoa(line), "never closed")
}

// An IPv6 address must be ::1 or in 2001:db8::/32, as an IPv4 one must be loopback or reserved.
func TestForeignIPv6AddressIsNamed(t *testing.T) {
	dir := copyDocs(t)
	mutate(t, dir, "CONTRIBUTING.md", func(s string) string { return s + "\nThe host is fe80::" + "1234:5678.\n" })
	wantFinding(t, StaticCheck(dir), "CONTRIBUTING.md", "fe80::"+"1234:5678", "2001:db8::/32")
	if fs := checkIPs("x", "::1 2001:db8::1 2001:DB8:0:1::5 [::]:9100 http://127.0.0.1:9100 sha256:abcdef0123"); len(fs) != 0 {
		t.Fatalf("loopback, the documentation range and ordinary text are allowed: %v", fs)
	}
}

// Negative control for the loopback and suite-check claims: the sentences the review found false are named when written again.
func TestRetiredClaimsAreNamed(t *testing.T) {
	dir := copyDocs(t)
	mutate(t, dir, "SECURITY.md", func(s string) string {
		return strings.Replace(s, "The suite checks some of the protections below and not others.", "Each protection below is a check in the suite.", 1)
	})
	mutate(t, dir, "README.md", func(s string) string {
		return strings.Replace(s, "- 2026-10-31: only the `scim` and `mcp` mocks refuse", "- 2026-10-31: the mocks listen on loopback only, by design; only the `scim` and `mcp` mocks refuse", 1)
	})
	fs := StaticCheck(dir)
	wantFinding(t, fs, "SECURITY.md", "each protection below is a check in the suite", "README.md", "listen on loopback only", "the scim and mcp mocks refuse a host")
	if len(fs) != 2 {
		t.Fatalf("exactly the two sentences are named, got:\n%s", messages(fs))
	}
}

// The Honest limits name the gaps the review measured, and each is dated.
func TestHonestLimitsNameTheKnownGaps(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	for _, it := range ParseDoc("README.md", data).Sections[limitsSection] {
		text.WriteString(it.Text + "\n")
	}
	for _, want := range []string{"9100", "9101", "18080", "syscall.Kill", "Setpgid", "virtual environment", "Python 3.12", "`scim` and `mcp`"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("Honest limits do not mention %q", want)
		}
	}
}

// The documents carry no hard-coded /tmp path: a predictable name in a shared directory is another user's to create first.
func TestDocumentCommandsUseNoFixedTempPath(t *testing.T) {
	for _, f := range []string{"README.md", "CONTRIBUTING.md"} {
		data, err := os.ReadFile(filepath.Join(repoRoot, f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "/tmp/") {
			t.Errorf("%s names a fixed /tmp path; use `mktemp -d`", f)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
