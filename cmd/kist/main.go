// Command kist keeps secrets in an age-encrypted file. See DESIGN.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/ibaurr/kist/internal/ui"
	"github.com/ibaurr/kist/internal/vault"
)

// Set at link time: -ldflags "-X main.version=v0.1.0 -X main.commit=abc123".
var (
	version = "dev"
	commit  = ""
)

// env carries everything a command touches outside its own arguments, so tests
// can run commands in-process with a temp directory and a scripted prompter.
type env struct {
	stdin                io.Reader
	stdout, stderr       io.Writer
	stdoutTTY, stderrTTY bool
	paths                vault.Paths
	prompt               ui.Prompter
	now                  func() time.Time
}

func main() {
	paths, err := vault.DefaultPaths(os.Getenv, os.UserHomeDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kist:", err)
		os.Exit(1)
	}
	e := &env{
		stdin:     os.Stdin,
		stdout:    os.Stdout,
		stderr:    os.Stderr,
		stdoutTTY: ui.IsTerminal(os.Stdout),
		stderrTTY: ui.IsTerminal(os.Stderr),
		paths:     paths,
		prompt:    ui.Terminal{},
		now:       time.Now,
	}
	os.Exit(run(os.Args[1:], e))
}

// usageError marks mistakes in how kist was invoked (exit status 2).
type usageError string

func (u usageError) Error() string { return string(u) }

const usageText = `usage: kist <command> [arguments]

  init                      create the identity and an empty vault
  set NAME [--stdin]        create or update a secret (value is never an argument)
  get NAME [--quiet]        print a secret
  list [--long]             list secret names
  delete NAME               remove a secret
  import [--overwrite] FILE import KEY=VALUE lines from a .env file
  export [--yes]            print KEY=VALUE lines
  recover                   regain access with the recovery key
  version                   print version information
`

type command func(e *env, args []string) error

var commands = map[string]command{
	"init":    cmdInit,
	"set":     cmdSet,
	"get":     cmdGet,
	"list":    cmdList,
	"delete":  cmdDelete,
	"import":  cmdImport,
	"export":  cmdExport,
	"recover": cmdRecover,
	"version": cmdVersion,
}

// run dispatches a command and returns the process exit status:
// 0 success, 1 failure, 2 usage error.
func run(args []string, e *env) int {
	if len(args) == 0 {
		fmt.Fprint(e.stderr, usageText)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(e.stdout, usageText)
		return 0
	}
	cmd, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(e.stderr, "kist: unknown command %q\n\n%s", args[0], usageText)
		return 2
	}
	err := cmd(e, args[1:])
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	default:
		fmt.Fprintln(e.stderr, "kist:", err)
		var u usageError
		if errors.As(err, &u) {
			return 2
		}
		return 1
	}
}

// parseArgs parses flags that may appear before or after positional arguments
// (`kist set NAME --stdin`), which the standard flag package does not do on
// its own. Everything after a literal "--" is positional.
func parseArgs(e *env, fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(e.stderr)
	var tail []string
	for i, a := range args {
		if a == "--" {
			args, tail = args[:i], args[i+1:]
			break
		}
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageError(err.Error())
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
	return append(pos, tail...), nil
}

func cmdVersion(e *env, args []string) error {
	if len(args) != 0 {
		return usageError("version takes no arguments")
	}
	c := commit
	if c == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					c = s.Value
				}
			}
		}
	}
	if c == "" {
		c = "unknown"
	}
	fmt.Fprintf(e.stdout, "kist %s (%s) %s\n", version, c, runtime.Version())
	return nil
}
