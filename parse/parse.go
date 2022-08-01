package parse

import (
        "fmt"
        "os"
        "regexp"
)

type optmap struct {
        OptEncrypt, OptDecrypt, OptList, OptPattern bool
        Dir, TargetDir, Pattern string
}

func ParseArgs(args []string) optmap  {
        var o optmap
        fail := func(msg string) {
                fmt.Fprintln(os.Stderr, msg + "\n")
                PrintUsage()
                os.Exit(1)
        }
        if len(args) == 0 {
                return o
        }
        switch args[0] {
                case "-e":
                        if len(args) != 3 {
                                fail("Invalid number of arguments.")
                        }
                        o.OptEncrypt = true
                        o.Dir = args[1]
                        o.TargetDir = args[2]
                case "-l":
                        if len(args) != 2 {
                                fail("Invalid number of arguments.")
                        }
                        o.OptList = true
                        o.Dir = args[1]
                case "-d":
                        switch len(args) {
                                case 4:
                                        if args[2] != "-p" {
                                                fail("Invalid argument.")
                                        }
                                        if m, _ := regexp.MatchString(`^\d+(-\d+)?(,\d+(-\d+)?)*$`, args[3]); !m {
                                                fail("Invalid pattern.")
                                        }
                                        o.OptPattern = true
                                        o.Pattern = args[3]
                                        fallthrough
                                case 2:
                                        o.OptDecrypt = true
                                        o.Dir = args[1]
                                default:
                                        fail("Invalid number of arguments.")
                        }
                default:
                        fail("Invalid argument.")
        }
        return o
}

func PrintUsage() {
	sUsage := `Usage:
        encrypt FILES (file or directory) and save encrypted content in TDIR
        $ chameleon -e FILES TDIR

        list encrypted files in DIR by number
        $ chameleon -l DIR

        decrypt directory DIR; optionally select only specific files with the selection pattern
        pattern: \d+(-\d+)?(,\d+(-\d+)?)*  ;  i.e. '5,7-12,17'
        $ chameleon -d DIR [-p SP]
`
	fmt.Println(sUsage)
}

