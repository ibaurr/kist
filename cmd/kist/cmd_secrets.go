package main

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/ibaurr/kist/internal/crypto"
	"github.com/ibaurr/kist/internal/ui"
	"github.com/ibaurr/kist/internal/vault"
)

func oneName(cmd string, pos []string) (string, error) {
	if len(pos) != 1 {
		// Deliberately does not echo the arguments: a user who typed a value
		// by mistake must not see it repeated.
		return "", usageError(fmt.Sprintf("%s takes exactly one argument, NAME (values are never accepted as arguments)", cmd))
	}
	if err := vault.ValidateName(pos[0]); err != nil {
		return "", usageError(err.Error())
	}
	return pos[0], nil
}

func cmdSet(e *env, args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	useStdin := fs.Bool("stdin", false, "read the value from standard input")
	pos, err := parseArgs(e, fs, args)
	if err != nil {
		return err
	}
	name, err := oneName("set", pos)
	if err != nil {
		return err
	}

	// Read piped input before the slow unlock so mistakes fail fast.
	var value []byte
	if *useStdin {
		if value, err = ui.ReadStdin(e.stdin); err != nil {
			return err
		}
		defer crypto.Wipe(value)
	}
	s, err := e.open()
	if err != nil {
		return err
	}
	if !*useStdin {
		// Prompt after unlocking, but before taking the file lock, so a slow
		// typist never blocks other kist processes.
		if value, err = e.prompt.Secret("Value for " + name + ": "); err != nil {
			return err
		}
		defer crypto.Wipe(value)
		if len(value) == 0 {
			return errors.New("empty value; nothing stored (use --stdin to store an empty value)")
		}
	}
	if err := vault.ValidateValue(string(value)); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return s.update(func(v *vault.Vault) error {
		return v.Set(name, string(value), e.now())
	})
}

func cmdGet(e *env, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	quiet := fs.Bool("quiet", false, "do not warn when printing to a terminal")
	fs.BoolVar(quiet, "q", false, "shorthand for --quiet")
	pos, err := parseArgs(e, fs, args)
	if err != nil {
		return err
	}
	name, err := oneName("get", pos)
	if err != nil {
		return err
	}
	s, err := e.open()
	if err != nil {
		return err
	}
	return s.view(func(v *vault.Vault) error {
		val, ok := v.Get(name)
		if !ok {
			return fmt.Errorf("no secret named %s", name)
		}
		if e.stdoutTTY {
			// Interactive: add a newline so the prompt isn't glued on, and warn.
			if !*quiet {
				fmt.Fprintln(e.stderr, "kist: warning: printing a secret to the terminal; it may stay in scrollback (silence with --quiet)")
			}
			val += "\n"
		}
		// Piped: the exact bytes, no decoration, so $(kist get X) and binary-
		// faithful redirection both work.
		_, err := fmt.Fprint(e.stdout, val)
		return err
	})
}

func cmdList(e *env, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	long := fs.Bool("long", false, "include the last-updated time")
	pos, err := parseArgs(e, fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageError("list takes no arguments")
	}
	s, err := e.open()
	if err != nil {
		return err
	}
	return s.view(func(v *vault.Vault) error {
		for _, n := range v.Names() {
			if *long {
				fmt.Fprintf(e.stdout, "%s\t%s\n", n, v.Secrets[n].UpdatedAt.Format(time.RFC3339))
			} else {
				fmt.Fprintln(e.stdout, n)
			}
		}
		return nil
	})
}

func cmdDelete(e *env, args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	pos, err := parseArgs(e, fs, args)
	if err != nil {
		return err
	}
	name, err := oneName("delete", pos)
	if err != nil {
		return err
	}
	s, err := e.open()
	if err != nil {
		return err
	}
	return s.update(func(v *vault.Vault) error {
		if !v.Delete(name) {
			return fmt.Errorf("no secret named %s", name)
		}
		return nil
	})
}
