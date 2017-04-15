package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var extOverride = map[string]string{
	"image/gif":        ".gif",
	"image/jpeg":       ".jpg",
	"image/png":        ".png",
	"image/svg+xml":    ".svg",
	"text/html":        ".html",
	"text/plain":       ".txt",
	"video/webm":       ".webm",
	"video/x-matroska": ".mkv",
}

type Store struct {
	path string
	cfg  *config
}

func Open(path string, c *config) (*Store, error) {
	err := os.Mkdir(path, 0700)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	return &Store{path, c}, err
}

func (s *Store) readToTemp(r io.Reader) (string, error) {
	tf, err := ioutil.TempFile(s.path, "tmp")
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

func (s *Store) Put(r io.Reader) (string, error) {
	r = newLimitReader(r, s.cfg.MaxSize)
	hw := sha256.New()
	r = io.TeeReader(r, hw)
	tn, err := s.readToTemp(r)
	if err != nil {
		return "", err
	}
	defer os.Remove(tn)
	hs := hw.Sum(nil)
	enc := base64.RawURLEncoding
	hashBytes := make([]byte, enc.EncodedLen(len(hs)))
	enc.Encode(hashBytes, hs)
	hash := string(hashBytes)
	return hash, os.Rename(tn, filepath.Join(s.path, hash))
}

func (s *Store) Open(name string) (*os.File, os.FileInfo, error) {
	f, err := os.Open(filepath.Join(s.path, name))
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, st, nil
}

type config struct {
	MaxSize uint64   `json:"max_size"`
	Keys    []string `json:"keys"`
}

func parseConfig(p string) (*config, error) {
	b, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, err
	}
	c := &config{}
	return c, json.Unmarshal(b, c)
}

func (s *Store) checkKey(key string) bool {
	k := []byte(key)
	for _, key := range s.cfg.Keys {
		b := []byte(key)
		if len(k) == len(b) && subtle.ConstantTimeCompare(k, b) == 1 {
			return true
		}
	}
	return false
}

func detectContentType(r io.Reader) (string, io.Reader, error) {
	preview := make([]byte, 512)
	n, err := io.ReadFull(r, preview)
	switch {
	case err == io.ErrUnexpectedEOF:
		preview = preview[:n]
		r = bytes.NewReader(preview)
	case err != nil:
		return "", nil, err
	default:
		r = io.MultiReader(bytes.NewReader(preview), r)
	}
	return http.DetectContentType(preview), r, nil
}

func extensionByType(typ string) string {
	ext, ok := extOverride[typ]
	if !ok {
		exts, err := mime.ExtensionsByType(typ)
		if err == nil && exts != nil && len(exts) == 0 {
			ext = "." + exts[0]
		}
	}
	return ext
}

func toHTTPError(err error) (string, int) {
	switch {
	case os.IsNotExist(err):
		return "404 Not Found", http.StatusNotFound
	case os.IsPermission(err):
		return "403 Forbidden", http.StatusForbidden
	case err == ErrSizeLimit:
		return "upload too big", 413
	}
	log.Print(err)
	return "500 Internal Server Error", http.StatusInternalServerError
}

func (s *Store) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		s.serveFile(w, req)
		return
	}
	if req.Method != "POST" {
		http.NotFound(w, req)
		return
	}
	k := req.FormValue("k")
	if !s.checkKey(k) {
		http.Error(w, http.StatusText(403), 403)
		return
	}
	f, fh, err := req.FormFile("f")
	if err != nil {
		log.Printf("Store.ServeHTTP: FormFile: %s", err)
		http.Error(w, http.StatusText(400), 400)
		return
	}
	defer f.Close()
	var r io.Reader = f
	ct := fh.Header.Get("Content-Type")
	if ct == "" || ct == "application/octet-stream" || !strings.Contains(ct, "/") {
		ct, r, err = detectContentType(r)
		if err != nil {
			log.Printf("Store.ServeHTTP: detectContentType: %s", err)
			http.Error(w, http.StatusText(400), 400)
			return
		}
	}
	name, err := s.Put(r)
	if err != nil {
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}
	u := url.URL{}
	u.Scheme = req.URL.Scheme
	u.Host = req.URL.Host
	u.Path = name + extensionByType(ct)
	fmt.Fprintf(w, "%s\n", u.String())
}

func splitExt(p string) (string, string) {
	for i, r := range p {
		if r == '.' {
			return p[:i], p[i:]
		}
	}
	return p, ""
}

func (s *Store) serveFile(w http.ResponseWriter, req *http.Request) {
	fn := path.Clean(req.URL.Path)
	if strings.ContainsAny(fn, "/\\") {
		http.NotFound(w, req)
		return
	}
	hash, ext := splitExt(fn)
	f, st, err := s.Open(hash)
	if err != nil {
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}
	defer f.Close()
	typ := mime.TypeByExtension(ext)
	if typ == "" {
		typ = "application/octet-stream"
	}
	w.Header().Set("Content-Type", typ)
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, req, hash, st.ModTime(), f)
}

func run() error {
	configPath := flag.String("config", "config.json", "configuration path")
	flag.Parse()
	c, err := parseConfig(*configPath)
	if err != nil {
		return err
	}
	s, err := Open("store", c)
	if err != nil {
		return err
	}
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", s))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "secup: %s\n", err)
		os.Exit(1)
	}
}
