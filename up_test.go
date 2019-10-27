package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

var testHasher = sha256.New

type testFile struct {
	name string
	fi   fileInfo
	b    []byte
}

var testFiles = []testFile{
	{"test", fileInfo{"filename", "ip address"}, []byte("test")},
	{"empty", fileInfo{}, []byte{}},
	{"1 byte", fileInfo{}, []byte{'a'}},
	{"partial info", fileInfo{From: "ip address"}, []byte("partialinfo")},
	{"max size", fileInfo{}, bytes.Repeat([]byte{'a'}, 5000)},
}

func hashBytes(b []byte, h func() hash.Hash) string {
	hw := h()
	hw.Write(b)
	return string(b64(hw.Sum(nil)))
}

func TestFileStore(t *testing.T) {
	t.Parallel()
	var storeDir = filepath.Join("testdata", "tmpstore1")
	fs, err := openFileStore(storeDir, testHasher)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storeDir)
	defer fs.Close()

	testPutGet := func(t *testing.T, f testFile) {
		hash, err := fs.Put(bytes.NewReader(f.b), &f.fi)
		if err != nil {
			t.Fatal(err)
		}
		want := hashBytes(f.b, testHasher)
		if hash != want {
			t.Fatalf("hash = %s, want %s", hash, want)
		}
		st, err := os.Stat(filepath.Join(storeDir, "public", hash))
		if err != nil {
			t.Fatal(err)
		}
		if sz := st.Size(); sz != int64(len(f.b)) {
			t.Errorf("st.Size() = %d, want %d", sz, len(f.b))
		}
		if mode := st.Mode(); mode != 0644 {
			t.Errorf("st.Mode() = 0%o, want 0644", mode)
		}
		r, fi, err := fs.Get(hash)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		b, err := ioutil.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(b, f.b) != 0 {
			t.Errorf("bytes = %#v, want %#v", b, f.b)
		}
		if *fi != f.fi {
			t.Errorf("fi = %#v, want %#v", fi, f.fi)
		}
	}

	t.Run("parallel put/get", func(t *testing.T) {
		for n := 0; n < 20; n++ {
			for _, f := range testFiles {
				t.Run(f.name, func(t *testing.T) {
					t.Parallel()
					testPutGet(t, f)
				})
			}
		}
	})

	fiModified := &fileInfo{"modified name", "modified ip address"}

	testModifiedInfo := func(t *testing.T, f testFile) {
		hash, err := fs.Put(bytes.NewReader(f.b), fiModified)
		if err != nil {
			t.Fatal(err)
		}
		want := hashBytes(f.b, testHasher)
		if hash != want {
			t.Errorf("hash = %s, want %s", hash, want)
		}
		fs.Get(hash)
		r, fi, err := fs.Get(hash)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if *fi != f.fi {
			t.Errorf("fi = %#v, want %#v", fi, f.fi)
		}
	}

	t.Run("modified info", func(t *testing.T) {
		for _, f := range testFiles {
			t.Run(f.name, func(t *testing.T) {
				t.Parallel()
				testModifiedInfo(t, f)
			})
		}
	})

	t.Run("reader error", func(t *testing.T) {
		r := iotest.TimeoutReader(bytes.NewReader([]byte("readererror")))
		_, err := fs.Put(r, &fileInfo{"name", "ip address"})
		if err == nil {
			t.Fatal("expected error")
		}
		ls, err := ioutil.ReadDir(storeDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range ls {
			if f.Name() != "public" && f.Name() != "db" {
				t.Errorf("stray temp file: %s", f.Name())
			}
		}
	})

	t.Run("concurrent open", func(t *testing.T) {
		_, err := openFileStore(storeDir, testHasher)
		if err == nil {
			t.Fatal("concurrent open worked")
		}
	})

	t.Run("nonexistent hashes", func(t *testing.T) {
		for _, h := range []string{"wronghash", ""} {
			_, _, err := fs.Get(h)
			if err == nil {
				t.Fatal("found nonexistent hash")
			}
		}
	})

	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
}

const (
	invalidKey = "invalid____________________"
	shortKey   = "shortKey"
	longKey    = "looooooooooooooooooooooooooooooooooooooooooooooooooooooooo" +
		"ooooooooooooooooooooooooooooooooooooooooooooooooongkey"
	goodKey  = "goodkey____________________"
	emptyKey = ""
)

var testKeys = []string{shortKey, longKey, goodKey, emptyKey, invalidKey}

var testConfig = config{
	ExternalURL: "http://example.org",
	MaxSize:     500,
	Seed:        []byte("wd394094f9c8ngdlofip08h4p8go7bdcv"),
	Keys:        []string{goodKey},
}

var testSeededHasher = seededHasher(testConfig.Seed)

func testLogger(t testing.TB) *log.Logger {
	t.Helper()
	return log.New(testWriter{TB: t}, t.Name()+" ",
		log.LstdFlags|log.Lshortfile|log.LUTC)
}

type testWriter struct {
	testing.TB
}

func (tw testWriter) Write(p []byte) (int, error) {
	tw.Helper()
	tw.Logf("%s", p)
	return len(p), nil
}

func multipartBody(key string, f testFile) ([]byte, string, error) {
	b := bytes.NewBuffer(nil)
	w := multipart.NewWriter(b)
	w.WriteField("k", key)
	name := f.fi.Name
	if name == "" {
		// go's multipart file parser doesn't like empty file names
		name = "filename"
	}
	fw, err := w.CreateFormFile("f", name)
	if err != nil {
		return nil, "", err
	}
	if _, err := fw.Write(f.b); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return b.Bytes(), w.FormDataContentType(), err
}

func TestFileHost(t *testing.T) {
	t.Parallel()
	var storeDir = filepath.Join("testdata", "tmpstore2")
	l := testLogger(t)
	h, err := openFileHost(storeDir, &testConfig, l)
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(storeDir)
	defer h.Close()

	testPutGet := func(t *testing.T, key string, f testFile) {
		b, ct, err := multipartBody(key, f)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "https://dummy.org/", bytes.NewReader(b))
		req.Header.Set("Content-Type", ct)
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		resp := rw.Result()
		body, _ := ioutil.ReadAll(resp.Body)
		if key != goodKey {
			if resp.StatusCode != 403 {
				t.Fatalf("accepted invalid key: %q\n%#v", key, resp)
			}
			return
		}
		if int64(len(b)) > testConfig.MaxSize {
			if resp.StatusCode != 413 && resp.StatusCode != 403 {
				t.Fatalf("accepted too large file: %#v\n%#v", f, resp)
			}
			return
		}
		if resp.StatusCode != 200 {
			t.Fatalf("status code != 200: %q\n%#v\n%#v", key, f, resp)
		}
		wantHash := hashBytes(f.b, testSeededHasher)
		wantPrefix := fmt.Sprintf("%s/%s", testConfig.ExternalURL, wantHash)
		if !strings.HasPrefix(string(body), wantPrefix) {
			t.Fatalf("incorrect response: %q", string(body))
		}
		req = httptest.NewRequest("GET", "https://dummy.org/"+wantHash, nil)
		rw = httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		resp = rw.Result()
		body, _ = ioutil.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("status code = %d, want 200", resp.StatusCode)
		}
		if bytes.Compare(body, f.b) != 0 {
			t.Fatalf("body = %q, want %q\n%#v", string(body), string(f.b), req.URL)
		}
	}

	t.Run("parallel put/get", func(t *testing.T) {
		for n := 0; n < 20; n++ {
			for _, f := range testFiles {
				for _, key := range testKeys {
					t.Run(f.name+"/"+key, func(t *testing.T) {
						t.Parallel()
						testPutGet(t, key, f)
					})
				}
			}
		}
	})

	// TODO: more malicious requests

	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}
