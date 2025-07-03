package db

import (
	"unicode"
)

func camelToSnake(c *string) *string {
	if c == nil {
		return nil
	}
	var o []rune
	for i, r := range *c {
		if unicode.IsUpper(r) {
			if i != 0 {
				o = append(o, '_')
			}
			r = unicode.ToLower(r)
		}
		o = append(o, r)
	}
	s := string(o)
	return &s
}

func like(s string) string {
	return "%" + s + "%"
}

func setIfEmpty(s1 *string, s2 string) {
	if *s1 == "" {
		*s1 = s2
	}
}

func toEmptyInterfaceSlice[T any](s []T) []interface{} {
	var ret []interface{}
	for _, v := range s {
		ret = append(ret, v)
	}
	return ret
}
