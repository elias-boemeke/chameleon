package main

import (
	"fmt"
	files "github.com/elias-boemeke/chameleon/files"
	parse "github.com/elias-boemeke/chameleon/parse"
	"os"
)

func main() {
	opts := parse.ParseArgs(os.Args[1:])
	switch {
	case opts.OptEncrypt:
		// prepare encrypt
		sf, std := opts.Dir, opts.TargetDir
		_, err := os.Stat(sf)
		if err != nil {
			fail(fmt.Sprintf("Unable to stat '%s': %s", sf, err))
		}
		_, err = os.Stat(std)
		if err == nil {
			fail(fmt.Sprintf("'%s' already exists. Remove or choose different output directory name.", std))
		}
		// encrypt
		files.Encrypt(sf, std)

	case opts.OptList:
		// prepare list
		sd := opts.Dir
		fi, err := os.Stat(sd)
		if err != nil {
			fail(fmt.Sprintf("Unable to stat '%s': %s", sd, err))
		}
		if !fi.IsDir() {
			fail(fmt.Sprintf("'%s': directory expected.", sd))
		}
		// list
		files.List(sd)

	case opts.OptDecrypt:
		// prepare decrypt
                sd := opts.Dir
                pattern := ""
                if opts.OptPattern {
                        pattern = opts.Pattern
                }
                files.Decrypt(sd, pattern)

	default:
		parse.PrintUsage()
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
