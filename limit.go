package main

import (
	"errors"
	"io"
)

var ErrSizeLimit = errors.New("read limit exceeded")

func newLimitReader(r io.Reader, lim int64) io.Reader { return &limitReader{r, lim} }

type limitReader struct {
	r io.Reader
	n int64
}

func (l *limitReader) Read(p []byte) (n int, err error) {
	if l.n <= 0 {
		return 0, ErrSizeLimit
	}
	if int64(len(p)) > l.n {
		p = p[0:l.n]
	}
	n, err = l.r.Read(p)
	l.n -= int64(n)
	return
}
