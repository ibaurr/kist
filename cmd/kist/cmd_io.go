package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ibaurr/kist/internal/crypto"
	"github.com/ibaurr/kist/internal/envfile"
	"github.com/ibaurr/kist/internal/vault"
)

func cmdImport(e *env, args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	overwrite := fs.Bool("overwrite", false, "replace secrets that already exist")
	pos, err := parseArgs(e, fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError("import takes exactly one argument, FILE")
	}
	path := pos[0]

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, envfile.MaxSize+1))
	if err != nil {
		return err
	}
	defer crypto.Wipe(data)

	// Parse and validate everything before unlocking: an import is all or
	// nothing, and errors name lines and secrets, never values.
	entries, err := envfile.Parse(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%s: no KEY=VALUE lines found", path)
	}
	for _, en := range entries {
		if err := vault.ValidateValue(en.Value); err != nil {
			return fmt.Errorf("%s: %s: %w", path, en.Name, err)
		}
	}

	s, err := e.open()
	if err != nil {
		return err
	}
	err = s.update(func(v *vault.Vault) error {
		if !*overwrite {
			var clash []string
			for _, en := range entries {
				if _, exists := v.Get(en.Name); exists {
					clash = append(clash, en.Name)
				}
			}
			if len(clash) > 0 {
				return fmt.Errorf("already in the vault: %s (nothing imported; use --overwrite to replace)", strings.Join(clash, ", "))
			}
		}
		for _, en := range entries {
			if err := v.Set(en.Name, en.Value, e.now()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stderr, "kist: imported %d secrets from %s\n", len(entries), path)
	fmt.Fprintf(e.stderr, "kist: reminder: %s still holds the secrets in plaintext; delete it\n", path)
	return nil
}

func cmdExport(e *env, args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "allow printing secrets to a terminal")
	pos, err := parseArgs(e, fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageError("export takes no arguments")
	}
	if e.stdoutTTY && !*yes {
		return usageError("refusing to print every secret to a terminal; pass --yes, or redirect stdout")
	}
	s, err := e.open()
	if err != nil {
		return err
	}
	return s.view(func(v *vault.Vault) error {
		entries := make([]envfile.Entry, 0, len(v.Secrets))
		for _, n := range v.Names() {
			entries = append(entries, envfile.Entry{Name: n, Value: v.Secrets[n].Value})
		}
		out := envfile.Format(entries)
		defer crypto.Wipe(out)
		_, err := e.stdout.Write(out)
		if errors.Is(err, io.ErrClosedPipe) {
			return nil
		}
		return err
	})
}
