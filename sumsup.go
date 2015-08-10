package main

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/text/unicode/norm"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

func usage() {
	fmt.Fprintf(os.Stderr, `sumsup: incremental sumsfile updater
Usage: sumsup [options] [FILE]...

  -c: check
  -u: update

  sumsup FILE...         Calculate
  sumsup -c SHA256SUMS   Check
  sumsup -u SHA256SUMS   Update
`)
}

var flag_check = flag.Bool("c", false, "check")
var flag_update = flag.Bool("u", false, "update")

// XXX: I can ignore text mode?
type Record struct {
	checksum string
	bin      bool
	path     string
}

type FileRecord struct {
	path string
	info os.FileInfo
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

func findfile(root string) ([]FileRecord, error) {
	files := []FileRecord{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if path != root && strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if path != root && strings.HasPrefix(info.Name(), ".") {
			return nil
		}
		files = append(files, FileRecord{path, info})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func normalize_for_key(path string) string {
	return strings.ToLower(norm.NFC.String(path))
}

func normalize_for_record(path string) string {
	return norm.NFC.String(path)
}

func cmd_check() error {
	sumsfile := flag.Arg(0)

	records, err := readsumsfile(sumsfile)
	if err != nil {
		return err
	}

	readerr := 0
	matcherr := 0
	for _, record := range records {
		checksum, err := sha256sum(record.path)
		if err != nil {
			fmt.Printf("%s: FAILED to read\n", record.path)
			readerr += 1
			continue
		}
		if checksum != record.checksum {
			fmt.Printf("%s: FAILED\n", record.path)
			matcherr += 1
			continue
		}
		fmt.Printf("%s: OK\n", record.path)
	}
	if readerr != 0 {
		fmt.Fprintf(os.Stderr, "WARNING: %d listed files could not be read\n", readerr)
	}
	if matcherr != 0 {
		fmt.Fprintf(os.Stderr, "WARNING: %d computed checksums dit NOT match\n", matcherr)
	}
	if readerr != 0 || matcherr != 0 {
		return errors.New("CHECK FAILED")
	}

	return nil
}

func cmd_update() error {
	sumsfile := flag.Arg(0)
	root := "."

	sumsfileinfo, err := os.Stat(sumsfile)
	if err != nil {
		return err
	}

	records, err := readsumsfile(sumsfile)
	if err != nil {
		return err
	}

	db := map[string]Record{}
	for _, record := range records {
		npath := normalize_for_key(record.path)
		db[npath] = record
	}

	files, err := findfile(root)
	if err != nil {
		return err
	}

	fs := map[string]FileRecord{}
	for _, file := range files {
		// Ignore SUMSFILE
		if os.SameFile(sumsfileinfo, file.info) {
			continue
		}
		npath := normalize_for_key(file.path)
		fs[npath] = file
	}

	uniq := map[string]bool{}
	for npath, _ := range db {
		uniq[npath] = true
	}
	for npath, _ := range fs {
		uniq[npath] = true
	}

	todo := make([]string, 0, len(uniq))
	for npath, _ := range uniq {
		todo = append(todo, npath)
	}
	sort.Strings(todo)

	newrecords := make([]Record, 0, len(todo))
	for _, npath := range todo {
		if _, ok := fs[npath]; !ok {
			fmt.Printf("%s: DELETED\n", db[npath].path)
		} else if _, ok := db[npath]; !ok {
			fmt.Printf("%s: ADDED\n", fs[npath].path)
			checksum, err := sha256sum(fs[npath].path)
			if err != nil {
				return err
			}
			newrecords = append(newrecords, Record{checksum, true, normalize_for_record(fs[npath].path)})
		} else if fs[npath].info.ModTime().After(sumsfileinfo.ModTime()) {
			fmt.Printf("%s: MODIFIED\n", fs[npath].path)
			checksum, err := sha256sum(fs[npath].path)
			if err != nil {
				return err
			}
			newrecords = append(newrecords, Record{checksum, true, normalize_for_record(fs[npath].path)})
		} else {
			newrecords = append(newrecords, db[npath])
		}
	}

	err = writesumsfile(sumsfile, newrecords)
	if err != nil {
		return err
	}

	return nil
}

func cmd_checksum() error {
	files := flag.Args()
	for _, file := range files {
		checksum, err := sha256sum(file)
		if err != nil {
			return err
		}
		fmt.Println(formatrecord(Record{checksum, true, normalize_for_record(file)}))
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
		if flag.NArg() != 1 {
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
