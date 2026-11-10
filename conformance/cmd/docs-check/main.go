// Command docs-check holds the public documents of the repository to what they say.
//
// It asserts the shape of README.md, SECURITY.md, CONTRIBUTING.md and LICENSE (the README's sections are present in
// the published order, every line under "What is measured", where there is one, carries a command, every limit is
// dated, no address but loopback and the documentation ranges), and then runs, from a fresh clone, every fenced block marked as a command
// and every measured command.
//
// A block's info string says how to run it:
//
//	```sh command                       run in the clone's root; it must exit 0
//	```sh command net                   the same, and it needs a loopback socket
//	```sh command needs=python3.12,venv the same, UNRUN where a requirement is unmet (python3.12, venv)
//	```sh serve wait=<url>              start in the background, wait for <url> to answer 200, stop at the document's end
//
// A block with none of these is shown, never run.
//
// Exit codes: 0 every assertion held and every command passed; 1 an assertion or a command failed;
// 2 the check could not start; 4 nothing failed but a command was UNRUN (it is never counted as a pass).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("docs-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "", "the repository root (default: the nearest parent of the current directory that holds spec/ and conformance/)")
	structure := fs.Bool("structure", false, "assert the documents' shape only; run no command and start no process")
	tree := fs.Bool("tree", false, "run the commands on a copy of the working tree instead of a clone of HEAD (use before the documents are committed)")
	timeout := fs.Duration("timeout", 15*time.Minute, "bound on one foreground command")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	r := *root
	if r == "" {
		var err error
		if r, err = findRoot(); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	findings := StaticCheck(r)
	for _, f := range findings {
		fmt.Fprintln(stdout, f)
	}
	if len(findings) == 0 {
		fmt.Fprintln(stdout, "PASS structure — every document and section is present in order, every measured line carries a command, every limit is dated")
	}
	if *structure {
		return summary(stdout, len(findings), 0, 0)
	}
	if len(findings) > 0 {
		fmt.Fprintln(stdout, "remark: commands were not run because the documents' shape is wrong; fix the lines above first")
		return summary(stdout, len(findings), 0, 0)
	}
	dir, err := Fresh(r, *tree)
	if dir != "" {
		defer os.RemoveAll(filepath.Dir(dir))
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	mode := "a clone of HEAD"
	if *tree {
		mode = "a copy of the working tree"
	}
	fmt.Fprintf(stdout, "remark: commands run from %s at %s\n", mode, dir)
	out := RunCommands(context.Background(), dir, Options{Root: r, Tree: *tree, Timeout: *timeout, Out: stdout})
	return summary(stdout, out.Fail, out.Pass, out.Unrun)
}

func summary(w io.Writer, fail, pass, unrun int) int {
	fmt.Fprintf(w, "SUMMARY %d failed, %d commands passed, %d UNRUN\n", fail, pass, unrun)
	switch {
	case fail > 0:
		return 1
	case unrun > 0:
		return 4
	}
	return 0
}

func findRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err == nil {
		p := strings.TrimSpace(string(out))
		if _, e := os.Stat(filepath.Join(p, "conformance")); e == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("docs-check: not inside the repository; pass --root <path of the repository root>")
}
