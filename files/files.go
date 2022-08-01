package files

import (
        "fmt"
        "crypto/sha256"
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "strings"
        "strconv"
        "io"
        "os"
        "time"
        "io/ioutil"
        "golang.org/x/term"
)

func cropSlash(s *string) {
        if (*s)[len(*s)-1] == '/' {
                *s = (*s)[:len(*s)-1]
        }
}

func Encrypt(sourceFiles, targetDir string) {
        // read source and prepare structure
        cropSlash(&sourceFiles)
        cropSlash(&targetDir)
	dirs, files := spanFileTree(sourceFiles)
	var filePairs [][2]string
	var hashMap map[string]bool = make(map[string]bool)
	for _, v := range files {
		var fhash string
		for {
			fhash = fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().Format(time.RFC3339Nano+v))))
			if _, ok := hashMap[fhash]; !ok {
				hashMap[fhash] = true
				break
			}
		}
		filePairs = append(filePairs, [2]string{v, fhash})
	}
        // read encryption key
        oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
        if err != nil {
                panic(err)
        }
        t := term.NewTerminal(os.Stdin, "")
        key, err := t.ReadPassword("password: ")
        term.Restore(int(os.Stdin.Fd()), oldState)
        // write files
	os.Mkdir(targetDir, 0755)
	writeEncryptFiles(targetDir, filePairs, key)
	writeEncryptIndex(targetDir, dirs, filePairs, key)
}

func List(tdir string) {
        cropSlash(&tdir)
        si := tdir + "/index"
        fi, err := os.Stat(si)
        if err != nil || fi.IsDir() {
                panic(err)
        }
        // read encryption key
        oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
        if err != nil {
                panic(err)
        }
        t := term.NewTerminal(os.Stdin, "")
        key, err := t.ReadPassword("password: ")
        term.Restore(int(os.Stdin.Fd()), oldState)
        // decrypt index file
        fc, _ := ioutil.ReadFile(si)
        noncesize := getNonceSizeAES256()
        if len(fc) < noncesize {
                fail(fmt.Sprintf("'%s': larger file size expected.", si))
        }
        pt := string(decryptAES256(key, fc[:noncesize], fc[noncesize:]))
        _, filePairs := readIndexStructure(pt)
        for i, fp := range filePairs {
                fmt.Println(fmt.Sprintf("[%d] %s", i+1, fp[0]))
        }
}


func Decrypt(tdir string, pattern string) {
        cropSlash(&tdir)
        si := tdir + "/index"
        fi, err := os.Stat(si)
        if err != nil || fi.IsDir() {
                panic(err)
        }
        // read encryption key
        oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
        if err != nil {
                panic(err)
        }
        t := term.NewTerminal(os.Stdin, "")
        key, err := t.ReadPassword("password: ")
        term.Restore(int(os.Stdin.Fd()), oldState)
        // decrypt index file
        fc, _ := ioutil.ReadFile(si)
        noncesize := getNonceSizeAES256()
        if len(fc) < noncesize {
                fail(fmt.Sprintf("'%s': larger file size expected.", si))
        }
        pt := string(decryptAES256(key, fc[:noncesize], fc[noncesize:]))
        dirs, filePairs := readIndexStructure(pt)
        // build file selection list
        selectionlist := buildSelectionList(len(filePairs), pattern)
        // decrypt
        writeDecryptFiles(tdir, key, dirs, filePairs, selectionlist)
}

func writeDecryptFiles(ctdir string, key string, dirs []string, filePairs [][2]string, selectionlist []bool) {
        // create directories
        for _, d := range dirs {
                fi, err := os.Stat(d)
                if err == nil && !fi.IsDir() {
                        fail(fmt.Sprintf("Failed to create directory '%s', non-existence expected.", d))
                } else if err != nil {
	                os.MkdirAll(d, 0755)
                }
        }
        // decrypt files if selected
        for i, fp := range filePairs {
                // assuming len(filePairs) == len(selectionlist)
                if selectionlist[i] {
                        ctfname := ctdir + "/" + fp[1]
                        ptfname := fp[0]
                        // check files
                        _, err := os.Stat(ptfname)
                        if err == nil {
                                fmt.Fprintln(os.Stderr, fmt.Sprintf("[warn] skipping file '%s', non-existence expected.", ptfname))
                                continue
                        }
                        fi, err := os.Stat(ctfname)
                        if err != nil {
                                fail(fmt.Sprintf("File '%d': %v", i+1, err))
                        }
                        if fi.IsDir() {
                                fail("Corrupted directory.")
                        }
                        // read ciphertext and decrypt
                        content, _ := ioutil.ReadFile(ctfname)
                        noncesize := getNonceSizeAES256()
                        if len(content) < noncesize {
                                fail(fmt.Sprintf("'%s': larger file size expected.", ctfname))
                        }
                        pt := string(decryptAES256(key, content[:noncesize], content[noncesize:]))
                        // write plaintext
		        os.WriteFile(ptfname, []byte(pt), 0644)
                }
        }
}

func writeEncryptFiles(targetDir string, filePairs [][2]string, key string) {
	for _, v := range filePairs {
                fc, _ := ioutil.ReadFile(v[0])
                nonce, ct := encryptAES256(key, fc)
                t := make([]byte, len(nonce) + len(ct))
                copy(t, nonce)
                copy(t[len(nonce):], ct)
		os.WriteFile(targetDir+"/"+v[1], t, 0644)
	}
}

func writeEncryptIndex(targetDir string, dirs []string, filePairs [][2]string, key string) {
	var indexStr string = "chameleon-index\n"
	for _, v := range dirs {
		indexStr = indexStr + v + "\ndir\n"
	}
	for _, v := range filePairs {
		indexStr = indexStr + v[0] + "\n" + v[1] + "\n"
	}
        // remove trailing newline
        if len(indexStr) > 0 && indexStr[len(indexStr)-1] == '\n' {
                indexStr = indexStr[:len(indexStr)-1]
        }
	fn := targetDir + "/index"
        nonce, ct := encryptAES256(key, []byte(indexStr))
        t := make([]byte, len(nonce) + len(ct))
        copy(t, nonce)
        copy(t[len(nonce):], ct)
	os.WriteFile(fn, t, 0644)
}

func readIndexStructure(plaintext string) (dirs []string, filePairs [][2]string) {
        lines := strings.Split(plaintext, "\n")
        if len(lines) < 1 {
                fail("Index file empty.")
        }
        header := "chameleon-index"
        if lines[0] != header {
                fail(fmt.Sprintf("Index file corrupted. Expected: '%s', Got: '%s'", header, lines[0]))
        }
        index := 1
        l := len(lines)
        for {
                if index + 1 >= l {
                        fail("Index file corrupted. Odd number of lines expected.")
                }
                if lines[index+1] == "dir" {
                        dirs = append(dirs, lines[index])
                } else {
                        filePairs = append(filePairs, [2]string{lines[index], lines[index+1]})
                }
                // iteration
                index += 2
                if index == l {
                        break
                }
        }
        return
}

func encryptAES256(key string, plaintext []byte) (nonce []byte, ciphertext []byte) {
        // prepare key
        var bk [32]byte = sha256.Sum256([]byte(key))
        // create 256 bit cipher
        c, err := aes.NewCipher(bk[:])
        if err != nil {
                panic(err)
        }
        // create AEAD GCM
        gcm, err := cipher.NewGCM(c)
        if err != nil {
                panic(err)
        }
        nonce = make([]byte, gcm.NonceSize())
        if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
                panic(err)
        }
        // seal plaintext
        ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
        return
}

func decryptAES256(key string, nonce []byte, ciphertext []byte) []byte {
        // prepare key
        var bk [32]byte = sha256.Sum256([]byte(key))
        // create 256 bit cipher
        c, err := aes.NewCipher(bk[:])
        if err != nil {
                panic(err)
        }
        // create AEAD GCM
        gcm, err := cipher.NewGCM(c)
        if err != nil {
                panic(err)
        }
        plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
        if err != nil {
                fail(fmt.Sprintf("Decryption failed: %v", err))
        }
        return plaintext
}

func buildSelectionList(max int, pattern string) []bool {
        sl := make([]bool, max)
        if pattern == "" {
                for i := range sl {
                        sl[i] = true
                }
                return sl
        }
        // assuming valid pattern
        parts := strings.Split(pattern, ",")
        for _, p := range parts {
                dspl := strings.Split(p, "-")
                switch len(dspl) {
                        case 1:
                                n, err := strconv.Atoi(dspl[0])
                                if err != nil {
                                        panic(err)
                                }
                                if n < 1 || n > max {
                                        fail(fmt.Sprintf("Number '%d' out of bounds.", n))
                                }
                                sl[n-1] = true
                        case 2:
                                n1, err := strconv.Atoi(dspl[0])
                                if err != nil {
                                        panic(err)
                                }
                                if n1 < 1 || n1 > max {
                                        fail(fmt.Sprintf("Number '%d' out of bounds.", n1))
                                }
                                n2, err := strconv.Atoi(dspl[1])
                                if err != nil {
                                        panic(err)
                                }
                                if n2 < 1 || n2 > max {
                                        fail(fmt.Sprintf("Number '%d' out of bounds.", n2))
                                }
                                if n1 > n2 {
                                        n1, n2 = n2, n1
                                }
                                for i := n1; i <= n2; i += 1 {
                                        sl[i-1] = true
                                }
                        default:
                                panic("irregular pattern")
                }
        }
        return sl
}

func spanFileTree(entryName string) (dirs []string, files []string) {
	fi, _ := os.Stat(entryName)
	if !fi.IsDir() {
		return []string{}, []string{entryName}
	} else {
		contents, _ := os.ReadDir(entryName)
		var rdirs []string
		var rfiles []string
		var bottomDir bool = true
		for _, v := range contents {
			if v.IsDir() {
				bottomDir = false
				subdirs, subfiles := spanFileTree(entryName + "/" + v.Name())
				for _, v := range subdirs {
					rdirs = append(rdirs, v)
				}
				for _, v := range subfiles {
					rfiles = append(rfiles, v)
				}
			} else {
				rfiles = append(rfiles, entryName+"/"+v.Name())
			}
		}
		if bottomDir {
			rdirs = append(rdirs, entryName)
		}
		return rdirs, rfiles
	}
}

func getNonceSizeAES256() int {
        var bk [32]byte
        c, err := aes.NewCipher(bk[:])
        if err != nil {
                panic(err)
        }
        gcm, err := cipher.NewGCM(c)
        if err != nil {
                panic(err)
        }
        return gcm.NonceSize()
}

func fail(msg string) {
        fmt.Fprintln(os.Stderr, msg)
        os.Exit(1)
}

