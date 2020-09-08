package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/google/shlex"
)

type Directive struct {
	Name     string
	Params   []string
	Children []*Directive
}

func (d *Directive) ParseParams(params ...*string) error {
	if len(d.Params) < len(params) {
		return fmt.Errorf("directive %q: want %v params, got %v", d.Name, len(params), len(d.Params))
	}
	for i, ptr := range params {
		if ptr == nil {
			continue
		}
		*ptr = d.Params[i]
	}
	return nil
}

func (d *Directive) ChildrenByName(name string) []*Directive {
	l := make([]*Directive, 0, len(d.Children))
	for _, child := range d.Children {
		if child.Name == name {
			l = append(l, child)
		}
	}
	return l
}

func (d *Directive) ChildByName(name string) *Directive {
	for _, child := range d.Children {
		if child.Name == name {
			return child
		}
	}
	return nil
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

		if len(words) == 1 && l[len(l)-1] == '}' {
			if cur == nil {
				return nil, fmt.Errorf("unexpected '}'")
			}
			cur = nil
			continue
		}

		var d *Directive
		if words[len(words)-1] == "{" && l[len(l)-1] == '{' {
			words = words[:len(words)-1]
			d = &Directive{Params: words}
			cur = d
			directives = append(directives, d)
		} else {
			d = &Directive{Name: words[0], Params: words[1:]}
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
