package main

import (
	"bufio"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"unicode"
)

func usage() {
	fmt.Fprintf(os.Stderr, `sumsup: incremental sumsfile updater
Usage: sumsup [options] [FILE]...

  -c: check
  -n: dryrun
  -u: update

  sumsup FILE...            Calculate checksum
  sumsup -c SHA256SUMS      Check
  sumsup -u SHA256SUMS [FILE]...
                            Update record if timestamp is newer than SHA256SUMS
                            Delete record if file is not exist
                            Add record for FILEs
`)
}

var flag_check = flag.Bool("c", false, "check")
var flag_dryrun = flag.Bool("n", false, "dryrun")
var flag_update = flag.Bool("u", false, "update")

// XXX: I can ignore text mode?
type Record struct {
	checksum string
	bin      bool
	path     string
}

func sha256sum(filepath string) (string, error) {
	r, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer r.Close()
	w := sha256.New()
	_, err = io.Copy(w, r)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%02x", w.Sum(nil)), nil
}

func ishex(s string) bool {
	for _, r := range s {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			return false
		}
	}
	return true
}

func parsesumsfile(f io.Reader) ([]Record, error) {
	records := []Record{}
	scanner := bufio.NewScanner(f)
	lnum := 1
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 {
			return nil, fmt.Errorf("parse error at line %d", lnum)
		}
		// /^(?P<SHA256CHECKSUM>\x{64})(?P<TYPE> [ *])(?P<PATH>.+)$/
		checksum := line[0:64]
		binmark := line[64:66]
		path := line[66:]
		if !ishex(checksum) {
			return nil, fmt.Errorf("parse error at line %d", lnum)
		}
		var bin bool
		if binmark == "  " {
			bin = false
		} else if binmark == " *" {
			bin = true
		} else {
			return nil, fmt.Errorf("parse error at line %d", lnum)
		}
		records = append(records, Record{checksum, bin, path})
		lnum += 1
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func readsumsfile(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parsesumsfile(f)
}

func formatrecord(record Record) string {
	if record.bin {
		return fmt.Sprintf("%s *%s", record.checksum, record.path)
	} else {
		return fmt.Sprintf("%s  %s", record.checksum, record.path)
	}
}

func writesumsfile(path string, records []Record) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, record := range records {
		fmt.Fprintln(f, formatrecord(record))
	}
	return nil
}

func cmd_check() error {
	sumsfile := flag.Arg(0)
	records, err := readsumsfile(sumsfile)
	if err != nil {
		return err
	}
	for _, record := range records {
		checksum, err := sha256sum(record.path)
		if err != nil {
			return err
		}
		if checksum == record.checksum {
			fmt.Printf("%s: OK\n", record.path)
		} else {
			fmt.Printf("%s: FAILED\n", record.path)
		}
	}
	return nil
}

func cmd_update() error {
	sumsfile := flag.Arg(0)
	files := flag.Args()[1:]

	sumsfileinfo, err := os.Stat(sumsfile)
	if err != nil {
		return err
	}

	records, err := readsumsfile(sumsfile)
	if err != nil {
		return err
	}

	db := map[string]Record{}
	fs := map[string]os.FileInfo{}
	todo := make([]string, 0, len(records))

	for _, root := range files {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			// Ignore SUMSFILE
			if os.SameFile(sumsfileinfo, info) {
				return nil
			}
			if _, ok := fs[path]; ok {
				return nil
			}
			fs[path] = info
			todo = append(todo, path)
			return nil
		})
		if err != nil {
			return err
		}
	}

	for _, record := range records {
		db[record.path] = record
		if _, ok := fs[record.path]; ok {
			continue
		}
		info, err := os.Stat(record.path)
		if err == nil {
			fs[record.path] = info
			todo = append(todo, record.path)
		} else if os.IsNotExist(err) {
			todo = append(todo, record.path)
		} else {
			return err
		}
	}

	sort.Strings(todo)

	newrecords := make([]Record, 0, len(todo))

	for _, path := range todo {
		if _, ok := fs[path]; !ok {
			fmt.Printf("%s: DELETED\n", path)
		} else if _, ok := db[path]; !ok {
			fmt.Printf("%s: ADDED\n", path)
			if !*flag_dryrun {
				checksum, err := sha256sum(path)
				if err != nil {
					return err
				}
				newrecords = append(newrecords, Record{checksum, true, path})
			}
		} else if fs[path].ModTime().After(sumsfileinfo.ModTime()) {
			fmt.Printf("%s: MODIFIED\n", path)
			if !*flag_dryrun {
				checksum, err := sha256sum(path)
				if err != nil {
					return err
				}
				newrecords = append(newrecords, Record{checksum, true, path})
			}
		} else {
			if !*flag_dryrun {
				newrecords = append(newrecords, db[path])
			}
		}
	}

	if !*flag_dryrun {
		err = writesumsfile(sumsfile, newrecords)
		if err != nil {
			return err
		}
	}

	return nil
}

func cmd_checksum() error {
	files := flag.Args()
	for _, root := range files {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			checksum, err := sha256sum(path)
			if err != nil {
				return err
			}
			fmt.Println(formatrecord(Record{checksum, true, path}))
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if *flag_check {
		if flag.NArg() != 1 {
			flag.Usage()
			os.Exit(2)
		}
		err := cmd_check()
		if err != nil {
			log.Fatal(err)
		}
	} else if *flag_update {
		if flag.NArg() < 1 {
			flag.Usage()
			os.Exit(2)
		}
		err := cmd_update()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		if flag.NArg() < 1 {
			flag.Usage()
			os.Exit(2)
		}
		err := cmd_checksum()
		if err != nil {
			log.Fatal(err)
		}
	}
}
