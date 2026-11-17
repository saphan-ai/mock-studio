package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const loopbackDenied = "UNRUN: loopback denied on this host"

// Options configure a run of the commands.
type Options struct {
	Root    string        // the repository whose documents are checked
	Tree    bool          // copy the working tree instead of cloning HEAD
	Timeout time.Duration // bound on one foreground command
	Out     io.Writer
}

// Outcome counts what the run did.
type Outcome struct {
	Pass, Fail, Unrun int
	Findings          []Finding
}

// LoopbackAllowed reports whether this host lets a process listen on loopback, with the error when it does not.
func LoopbackAllowed() (bool, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false, err
	}
	l.Close()
	return true, nil
}

// Fresh makes a clean copy of the repository in a new directory: a clone of HEAD, or with tree the files of the
// working tree that git would add (tracked, and untracked but not ignored).
func Fresh(root string, tree bool) (string, error) {
	dir, err := os.MkdirTemp("", "docs-check-")
	if err != nil {
		return "", err
	}
	dst := filepath.Join(dir, "mocks-studio")
	if !tree {
		if out, err := exec.Command("git", "clone", "--quiet", root, dst).CombinedOutput(); err != nil {
			return dir, fmt.Errorf("git clone of %s failed: %v: %s; commit the documents first or pass --tree", root, err, out)
		}
		return dst, nil
	}
	list, err := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output()
	if err != nil {
		return dir, fmt.Errorf("git ls-files in %s failed: %v", root, err)
	}
	for _, rel := range strings.Split(string(list), "\x00") {
		if rel == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // listed and deleted in the working tree
		}
		to := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			return dir, err
		}
		if err := os.WriteFile(to, data, 0o644); err != nil {
			return dir, err
		}
	}
	return dst, nil
}

// RunCommands runs, from the fresh copy at dir, every block of the documents marked `command` or `serve` and every
// measured command, in document order. A command that needs a socket on a host that forbids one is UNRUN.
func RunCommands(ctx context.Context, dir string, o Options) Outcome {
	var res Outcome
	netOK, netErr := LoopbackAllowed()
	if !netOK {
		fmt.Fprintf(o.Out, "remark: this host refuses a loopback listener (%v); every command marked `net` or `serve` is UNRUN\n", netErr)
	}
	for _, name := range []string{"README.md", "CONTRIBUTING.md"} {
		d, err := ReadDoc(filepath.Join(dir, name), name)
		if err != nil {
			res.fail(o, Finding{File: name, Msg: "the file cannot be read: " + err.Error()})
			continue
		}
		runDoc(ctx, dir, d, netOK, o, &res)
	}
	return res
}

func (r *Outcome) fail(o Options, f Finding) {
	r.Fail++
	r.Findings = append(r.Findings, f)
	fmt.Fprintln(o.Out, f)
}

func (r *Outcome) unrun(o Options, file string, line int, reason, what string) {
	r.Unrun++
	fmt.Fprintf(o.Out, "UNRUN %s:%d — %s (%s)\n", file, line, reason, what)
}

func (r *Outcome) pass(o Options, file string, line int, what string) {
	r.Pass++
	fmt.Fprintf(o.Out, "PASS %s:%d — %s\n", file, line, what)
}

type server struct {
	cmd *exec.Cmd
	log *bytes.Buffer
}

func runDoc(ctx context.Context, dir string, d *Doc, netOK bool, o Options, res *Outcome) {
	var servers []*server
	defer func() {
		for _, s := range servers {
			s.stop()
		}
	}()
	// Blocks and measured bullets in the order they appear in the file.
	type step struct {
		line    int
		block   *Block
		bullet  *Item
		measure string
	}
	var steps []step
	for i := range d.Blocks {
		b := &d.Blocks[i]
		if b.Has("command") || b.Has("serve") {
			steps = append(steps, step{line: b.Line, block: b})
		}
	}
	if d.Name == "README.md" {
		items := d.Sections[measuredSection]
		for i := range items {
			if items[i].Bullet {
				if c, ok := MeasuredCommand(items[i].Text); ok {
					steps = append(steps, step{line: items[i].Line, bullet: &items[i], measure: c})
				}
			}
		}
	}
	sortSteps := func() {
		for i := 1; i < len(steps); i++ {
			for j := i; j > 0 && steps[j].line < steps[j-1].line; j-- {
				steps[j], steps[j-1] = steps[j-1], steps[j]
			}
		}
	}
	sortSteps()
	for _, st := range steps {
		if st.block != nil {
			b := st.block
			what := firstLine(b.Script)
			if n := b.Option("needs"); n != "" {
				if why := unmet(n); why != "" {
					res.unrun(o, d.Name, b.Line, "needs "+n+": "+why, what)
					continue
				}
			}
			if (b.Has("net") || b.Has("serve")) && !netOK {
				res.unrun(o, d.Name, b.Line, loopbackDenied, what)
				continue
			}
			if b.Has("serve") {
				s, err := startServer(dir, b, o)
				if err != nil {
					res.fail(o, Finding{File: d.Name, Line: b.Line, Msg: err.Error() + " — " + what})
					continue
				}
				servers = append(servers, s)
				res.pass(o, d.Name, b.Line, "serving: "+what)
				continue
			}
			out, err := runShell(ctx, dir, b.Script, o.Timeout)
			if err != nil {
				res.fail(o, Finding{File: d.Name, Line: b.Line, Msg: fmt.Sprintf("the command failed: %v — %s\n%s", err, what, tail(out, 20))})
				continue
			}
			res.pass(o, d.Name, b.Line, what)
			continue
		}
		// A measured bullet: the command prints the number the line states.
		out, err := runShell(ctx, dir, st.measure, o.Timeout)
		if err != nil {
			res.fail(o, Finding{File: d.Name, Line: st.line, Msg: fmt.Sprintf("the measured command failed: %v — %s\n%s", err, st.measure, tail(out, 20))})
			continue
		}
		m := leadNumRe.FindStringSubmatch(st.bullet.Text)
		if m == nil {
			res.fail(o, Finding{File: d.Name, Line: st.line, Msg: fmt.Sprintf("the measured line does not start with the number its command prints, so nothing compares them — %s; start the line with the number", st.measure)})
			continue
		}
		want, _ := strconv.Atoi(m[1])
		got, convErr := strconv.Atoi(strings.TrimSpace(out))
		if convErr != nil || got != want {
			res.fail(o, Finding{File: d.Name, Line: st.line, Msg: fmt.Sprintf("the line states %d but the command prints %q — %s; correct the number to what the command prints", want, strings.TrimSpace(out), st.measure)})
			continue
		}
		res.pass(o, d.Name, st.line, "measured: "+st.measure)
	}
}

// unmet returns why a requirement is not met on this host, or "" when it is. A list of requirements is separated by
// commas and the first one unmet is named. Known: python3.12 (python3 is that version or newer) and venv (python3
// can create a virtual environment, which a Debian or Ubuntu host without python3-venv cannot).
func unmet(need string) string {
	for _, one := range strings.Split(need, ",") {
		if why := unmetOne(one); why != "" {
			return why
		}
	}
	return ""
}

func unmetOne(need string) string {
	switch need {
	case "python3.12":
		out, err := exec.Command("python3", "-c", "import sys; print('%d.%d' % sys.version_info[:2]); sys.exit(0 if sys.version_info >= (3, 12) else 1)").Output()
		if err != nil {
			return "python3 is " + strings.TrimSpace(string(out)) + " here, or absent"
		}
	case "venv":
		if err := exec.Command("python3", "-c", "import ensurepip, venv").Run(); err != nil {
			return "python3 cannot make a virtual environment here (on Debian or Ubuntu, install python3-venv)"
		}
	default:
		return "unknown requirement " + need
	}
	return ""
}

func runShell(ctx context.Context, dir, script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-ec", script)
	cmd.Dir = dir
	// stdout alone is the measurement a number is read from; stderr is kept apart and shown only on failure.
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outBuf, &errBuf
	if err := cmd.Run(); err != nil {
		return outBuf.String() + errBuf.String(), err
	}
	return outBuf.String(), nil
}

func startServer(dir string, b *Block, o Options) (*server, error) {
	s := &server{log: &bytes.Buffer{}}
	s.cmd = exec.Command("sh", "-ec", b.Script)
	s.cmd.Dir = dir
	s.cmd.Stdout, s.cmd.Stderr = s.log, s.log
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := s.cmd.Start(); err != nil {
		return nil, fmt.Errorf("the server could not start: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- s.cmd.Wait() }()
	url := b.Option("wait")
	if url == "" {
		s.stop()
		return nil, fmt.Errorf("a `serve` block must name the URL that shows it is up, as wait=<url>")
	}
	deadline := time.Now().Add(3 * time.Minute)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			return nil, fmt.Errorf("the server exited before it answered %s (%v):\n%s", url, err, tail(s.log.String(), 20))
		default:
		}
		if resp, err := client.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return s, nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	s.stop()
	return nil, fmt.Errorf("the server did not answer 200 on %s within 3 minutes:\n%s", url, tail(s.log.String(), 20))
}

func (s *server) stop() {
	if s.cmd == nil || s.cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGTERM)
	time.Sleep(500 * time.Millisecond)
	_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
