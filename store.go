package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/boltdb/bolt"
)

var filesBucket = []byte("files")

type store struct {
	db   *bolt.DB
	path string
	seed []byte
}

type fileInfo struct {
	Name string `json:"name,omitempty"`
	From string `json:"ip,omitempty"`
}

type file struct {
	r     *os.File
	mtime time.Time
	info  *fileInfo
}

func openStore(path string, seed []byte) (*store, error) {
	err := os.MkdirAll(filepath.Join(path, "public"), 0700)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(path, "db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(filesBucket)
		return err
	})
	return &store{db, path, seed}, err
}

func (s *store) readToTemp(r io.Reader) (string, error) {
	tf, err := ioutil.TempFile(s.path, "up-")
	if err != nil {
		return "", err
	}
	tn := tf.Name()
	_, err = io.Copy(tf, r)
	tf.Close()
	if err != nil {
		os.Remove(tn)
	}
	return tn, err
}

func (s *store) put(r io.Reader, fi *fileInfo) (string, error) {
	hw := sha256.New()
	hw.Write(s.seed)
	r = io.TeeReader(r, hw)
	tn, err := s.readToTemp(r)
	if err != nil {
		return "", err
	}
	defer os.Remove(tn)
	hs := hw.Sum(nil)
	enc := base64.RawURLEncoding
	hash := make([]byte, enc.EncodedLen(len(hs)))
	enc.Encode(hash, hs)
	fib, err := json.Marshal(fi)
	if err != nil {
		return "", err
	}
	exists := false
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(filesBucket)
		if b.Get(hash) != nil {
			exists = true
			return nil
		}
		return b.Put(hash, fib)
	})
	if err != nil || exists {
		return string(hash), err
	}
	return string(hash), os.Rename(tn, filepath.Join(s.path, "public", string(hash)))
}

func (s *store) get(hash string) (*file, error) {
	fi := &fileInfo{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(filesBucket).Get([]byte(hash))
		if b == nil {
			return errNotExist
		}
		return json.Unmarshal(b, fi)
	})
	if err != nil && err != errNotExist /* old files don't have db entries */ {
		return nil, err
	}
	f, err := os.Open(filepath.Join(s.path, "public", hash))
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &file{f, st.ModTime(), fi}, nil
}
