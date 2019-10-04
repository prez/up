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
	fi   FileInfo
	b    []byte
}

var testFiles = []testFile{
	{"test", FileInfo{"filename", "ip address"}, []byte("test")},
	{"empty", FileInfo{}, []byte{}},
	{"1 byte", FileInfo{}, []byte{'a'}},
	{"partial info", FileInfo{From: "ip address"}, []byte("partialinfo")},
	{"max size", FileInfo{}, bytes.Repeat([]byte{'a'}, 5000)},
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
		t.Error(err)
	}
	defer os.RemoveAll(storeDir)
	defer fs.Close()

	testPutGet := func(t *testing.T, f testFile) {
		hash, err := fs.Put(bytes.NewReader(f.b), &f.fi)
		if err != nil {
			t.Error(err)
		}
		want := hashBytes(f.b, testHasher)
		if hash != want {
			t.Errorf("hash = %s, want %s", hash, want)
		}
		st, err := os.Stat(filepath.Join(storeDir, "public", hash))
		if err != nil {
			t.Error(err)
		}
		if sz := st.Size(); sz != int64(len(f.b)) {
			t.Errorf("st.Size() = %d, want %d", sz, len(f.b))
		}
		if mode := st.Mode(); mode != 0600 {
			t.Errorf("st.Mode() = %o, want 0600", mode)
		}
		r, fi, err := fs.Get(hash)
		if err != nil {
			t.Error(err)
		}
		defer r.Close()
		b, err := ioutil.ReadAll(r)
		if err != nil {
			t.Error(err)
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

	fiModified := &FileInfo{"modified name", "modified ip address"}

	testModifiedInfo := func(t *testing.T, f testFile) {
		hash, err := fs.Put(bytes.NewReader(f.b), fiModified)
		if err != nil {
			t.Error(err)
		}
		want := hashBytes(f.b, testHasher)
		if hash != want {
			t.Errorf("hash = %s, want %s", hash, want)
		}
		fs.Get(hash)
		r, fi, err := fs.Get(hash)
		if err != nil {
			t.Error(err)
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
		_, err := fs.Put(r, &FileInfo{"name", "ip address"})
		if err == nil {
			t.Error("expected error")
		}
		ls, err := ioutil.ReadDir(storeDir)
		if err != nil {
			t.Error(err)
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
			t.Error("concurrent open worked")
		}
	})

	t.Run("nonexistent hashes", func(t *testing.T) {
		for _, h := range []string{"wronghash", ""} {
			_, _, err := fs.Get(h)
			if err == nil {
				t.Error("found nonexistent hash")
			}
		}
	})

	if err := fs.Close(); err != nil {
		t.Error(err)
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
	Keys:        []string{shortKey, longKey, goodKey, emptyKey},
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

func TestFileHost(t *testing.T) {
	t.Parallel()
	var storeDir = filepath.Join("testdata", "tmpstore2")
	l := testLogger(t)
	h, err := openFileHost(storeDir, true, &testConfig, l)
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(storeDir)
	defer h.Close()

	testPutGet := func(t *testing.T, key string, f testFile) {
		b := bytes.NewBuffer(nil)
		w := multipart.NewWriter(b)
		w.WriteField("k", key)
		name := f.fi.Name
		if name == "" {
			name = "filename"
		}
		fw, err := w.CreateFormFile("f", name)
		if err != nil {
			t.Error(err)
		}
		if _, err := fw.Write(f.b); err != nil {
			t.Error(err)
		}
		if err := w.Close(); err != nil {
			t.Error(err)
		}
		s := b.String()
		req := httptest.NewRequest("POST", "https://dummy.org/", b)
		req.Header.Set("Content-Type", w.FormDataContentType())
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		resp := rw.Result()
		body, _ := ioutil.ReadAll(resp.Body)
		if key != goodKey {
			if resp.StatusCode != 403 {
				t.Errorf("accepted invalid key: %q\n%#v", key, resp)
			}
			return
		}
		if int64(len(f.b)) > testConfig.MaxSize {
			if resp.StatusCode != 413 && resp.StatusCode != 403 {
				t.Errorf("accepted too large file: %#v\n%#v", f, resp)
			}
			return
		}
		if resp.StatusCode != 200 {
			t.Errorf("status code != 200: %q\n%#v\n%#v\n%q", key, f, resp, s)
		}
		wantHash := hashBytes(f.b, testSeededHasher)
		wantPrefix := fmt.Sprintf("%s/%s", testConfig.ExternalURL, wantHash)
		if !strings.HasPrefix(string(body), wantPrefix) {
			t.Errorf("incorrect response: %q", string(body))
		}
		req = httptest.NewRequest("GET", "https://dummy.org/"+wantHash, nil)
		rw = httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		resp = rw.Result()
		body, _ = ioutil.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Errorf("status code = %d, want 200", resp.StatusCode)
		}
		if bytes.Compare(body, f.b) != 0 {
			t.Errorf("body = %q, want %q\n%#v", string(body), string(f.b),
				req.URL)
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

	t.Run("https redirect", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://dummy.org/", nil)
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		resp := rw.Result()
		if resp.StatusCode != 301 {
			t.Errorf("status code = %d, want 301", resp.StatusCode)
		}
	})
}
