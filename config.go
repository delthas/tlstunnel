package main

import (
	"os"
	"io"
	"bufio"
	"fmt"

	"github.com/google/shlex"
)

type Directive struct {
	Params []string
	Children []*Directive
}

func Load(path string) ([]*Directive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return Parse(f)
}

func Parse(r io.Reader) ([]*Directive, error) {
	scanner := bufio.NewScanner(r)

	var directives []*Directive
	var cur *Directive
	for scanner.Scan() {
		l := scanner.Text()
		words, err := shlex.Split(l)
		if err != nil {
			return directives, fmt.Errorf("failed to parse config file: %v", err)
		} else if len(words) == 0 {
			continue
		}

		if len(words) == 1 && l[len(l) - 1] == '}' {
			if cur == nil {
				return nil, fmt.Errorf("unexpected '}'")
			}
			cur = nil
			continue
		}

		var d *Directive
		if words[len(words) - 1] == "{" && l[len(l) - 1] == '{' {
			d = &Directive{
				Params: words[:len(words) - 1],
			}
			cur = d
			directives = append(directives, d)
		} else {
			d = &Directive{Params: words}
			if cur != nil {
				cur.Children = append(cur.Children, d)
			} else {
				directives = append(directives, d)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	return directives, nil
}
