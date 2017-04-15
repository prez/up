package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var extOverride = map[string]string{
	"application/octet-stream": "bin",
	"image/gif":                "gif",
	"image/jpeg":               "jpg",
	"image/png":                "png",
	"image/svg+xml":            "svg",
	"text/html":                "html",
	"text/plain":               "txt",
	"video/webm":               "webm",
	"video/x-matroska":         "mkv",
}

type config struct {
	ExtURL  string   `json:"external_url"`
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

type Store struct {
	path string
	cfg  *config
}

func Open(dir string, c *config) (*Store, error) {
	os.Mkdir(dir, 0755)
	st, err := os.Stat(dir)
	if err == nil && !st.IsDir() {
		err = errors.New("store is not a directory")
	}
	return &Store{dir, c}, err
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

func (s *Store) Upload(r io.Reader, ext string) (string, error) {
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
	name := string(hashBytes) + "." + ext
	return name, os.Rename(tn, filepath.Join(s.path, name))
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

func mimeExtension(typ string) string {
	ext, ok := extOverride[typ]
	if !ok {
		exts, err := mime.ExtensionsByType(typ)
		if err == nil && exts != nil && len(exts) == 0 {
			ext = exts[0]
		}
	}
	if ext == "" {
		ext = "bin"
	}
	return ext
}

func (s *Store) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		// placeholder, should be served by web server directly
		http.FileServer(http.Dir(s.path)).ServeHTTP(w, req)
		return
	}
	if req.Method != "POST" {
		http.NotFound(w, req)
		return
	}
	k := req.FormValue("k")
	if !s.checkKey(k) {
		http.NotFound(w, req)
		return
	}
	f, fh, err := req.FormFile("f")
	if err != nil {
		log.Printf("Store.ServeHTTP: FormFile: %s", err)
		http.NotFound(w, req)
		return
	}
	defer f.Close()
	var r io.Reader = f
	ct := fh.Header.Get("Content-Type")
	if ct == "" || ct == "application/octet-stream" || !strings.Contains(ct, "/") {
		ct, r, err = detectContentType(r)
		if err != nil {
			log.Printf("Store.ServeHTTP: detectContentType: %s", err)
			http.NotFound(w, req)
			return
		}
	}
	name, err := s.Upload(r, mimeExtension(ct))
	if err != nil {
		log.Printf("Store.ServeHTTP: Upload: %s", err)
		http.NotFound(w, req)
		return
	}
	fmt.Fprintf(w, "%s/%s\n", s.cfg.ExtURL, name)
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
	http.Handle("/", s)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "secup: %s\n", err)
		os.Exit(1)
	}
}
