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
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/boltdb/bolt"
)

var extOverride = map[string]string{
	"image/gif":                ".gif",
	"image/jpeg":               ".jpg",
	"image/png":                ".png",
	"image/svg+xml":            ".svg",
	"text/html":                ".html",
	"text/plain":               ".txt",
	"video/webm":               ".webm",
	"video/x-matroska":         ".mkv",
	"application/octet-stream": "",
}

var (
	errUnauthorized = errors.New("unauthorized request")
	errBadRequest   = errors.New("bad request")
	errNotExist     = errors.New("entry does not exist")
	errSizeLimit    = errors.New("size limit exceeded")
)

var filesBucket = []byte("files")

type config struct {
	ExternalURL string            `json:"external_url"`
	ExtTypes    map[string]string `json:"ext_types"`
	MaxSize     int64             `json:"max_size"`
	Seed        []byte            `json:"seed"`
	Keys        []string          `json:"keys"`

	XAccel     bool   `json:"x_accel_enable"`
	XAccelPath string `json:"x_accel_path"`
}

func parseConfig(p string) (*config, error) {
	b, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, err
	}
	c := &config{}
	return c, json.Unmarshal(b, c)
}

type fileHost struct {
	db     *bolt.DB
	path   string
	config *config
	logger *log.Logger
}

func newFileHost(p string, c *config, l *log.Logger) (*fileHost, error) {
	err := os.MkdirAll(filepath.Join(p, "public"), 0700)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(p, "db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(filesBucket)
		return err
	})
	return &fileHost{db, p, c, l}, err
}

func (s *fileHost) readToTemp(r io.Reader) (string, error) {
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

type fileInfo struct {
	Name string `json:"name,omitempty"`
	From string `json:"ip,omitempty"`
}

func (s *fileHost) put(r io.Reader, fi *fileInfo) (string, error) {
	hw := sha256.New()
	hw.Write(s.config.Seed)
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
	if exists || err != nil {
		return string(hash), err
	}
	err = os.Rename(tn, s.pathTo(string(hash)))
	if err != nil {
		return "", err
	}
	return string(hash), os.Chmod(s.pathTo(string(hash)), 0644)
}

func (s *fileHost) pathTo(hash string) string { return filepath.Join(s.path, "public", hash) }

func (s *fileHost) get(hash string) (*fileInfo, error) {
	fi := &fileInfo{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(filesBucket).Get([]byte(hash))
		if b == nil {
			return nil
		}
		return json.Unmarshal(b, fi)
	})
	return fi, err
}

func toHTTPError(err error) (int, string) {
	switch {
	case os.IsNotExist(err) || err == errNotExist:
		return 404, "Not Found"
	case os.IsPermission(err) || err == errUnauthorized:
		return 403, "Forbidden"
	case err == errBadRequest:
		return 400, "Bad Request"
	case err == errSizeLimit:
		return 413, "Payload Too Large"
	}
	return 500, "Internal Server Error"
}

// XXX: doesn't support X-Forwarded-For
func remoteAddr(req *http.Request) string {
	h := req.Header.Get("X-Real-IP")
	if h == "" {
		h, _, _ = net.SplitHostPort(req.RemoteAddr)
	}
	return h
}

func (s *fileHost) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var err error
	switch req.Method {
	case "POST":
		err = s.uploadFile(w, req)
	case "GET":
		err = s.serveFile(w, req)
	default:
		http.Error(w, "Not Found", 404)
		return
	}
	if err != nil {
		s.logger.Printf("%s: %s", remoteAddr(req), err)
		code, text := toHTTPError(err)
		http.Error(w, text, code)
	}
}

func (s *fileHost) checkKey(key string) bool {
	if len(key) < 20 || len(key) > 100 {
		return false // sanity check
	}
	k := []byte(key)
	for _, key := range s.config.Keys {
		b := []byte(key)
		if len(k) == len(b) && subtle.ConstantTimeCompare(k, b) == 1 {
			return true
		}
	}
	return false
}

// clean up file paths from content-disposition headers
func fixMultipartPath(s string) string {
	if i := strings.LastIndexAny(s, "\\//"); i != -1 {
		s = s[i+1:]
	}
	if s == "-" || len(s) > 78 {
		return ""
	}
	return s
}

// split file name on extension
func splitExt(p string) (string, string) {
	if i := strings.IndexByte(p, '.'); i != -1 {
		return p[:i], p[i:]
	}
	return p, ""
}

func detectContentType(r io.Reader, name string, typ string) (string, io.Reader, error) {
	ty, _, err := mime.ParseMediaType(typ)
	if err == nil && ty != "application/octet-stream" {
		return typ, r, nil
	}
	_, ext := splitExt(name)
	if typ := mime.TypeByExtension(ext); typ != "" {
		return typ, r, nil
	}
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
	typ, _, _ = mime.ParseMediaType(typ)
	if ext, ok := extOverride[typ]; ok {
		return ext
	}
	exts, err := mime.ExtensionsByType(typ)
	if err == nil && exts != nil && len(exts) != 0 {
		return exts[0]
	}
	return ""
}

func (s *fileHost) uploadFile(w http.ResponseWriter, req *http.Request) error {
	if req.ContentLength > s.config.MaxSize {
		return errSizeLimit // attempt to return a nice error message
	}
	req.Body = http.MaxBytesReader(w, req.Body, s.config.MaxSize)
	k := req.FormValue("k")
	if !s.checkKey(k) {
		return errUnauthorized
	}
	f, fh, err := req.FormFile("f")
	if err != nil {
		return err
	}
	defer f.Close()
	typ, r, err := detectContentType(f, fh.Filename, fh.Header.Get("Content-Type"))
	if err != nil {
		return err
	}
	fi := fileInfo{Name: fixMultipartPath(fh.Filename), From: remoteAddr(req)}
	name, err := s.put(r, &fi)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s/%s%s\n",
		s.config.ExternalURL, name, extensionByType(typ))
	return err
}

// validates and splits a path like <hash>.ext
func cleanPath(p string) (string, string) {
	p = strings.TrimLeft(path.Clean(p), "/")
	if strings.ContainsAny(p, "/\\") {
		return "", ""
	}
	return splitExt(p)
}

// escape file name for content-disposition header
var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func serveHeaders(w http.ResponseWriter, typ string, fi *fileInfo) {
	w.Header().Set("Content-Type", typ)
	if n := fi.Name; n != "" {
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`inline; filename="%s"`, quoteEscaper.Replace(n)))
	}
}

func (s *fileHost) serveFile(w http.ResponseWriter, req *http.Request) error {
	hash, ext := cleanPath(req.URL.Path)
	if hash == "" {
		return errNotExist
	}
	fi, err := s.get(hash)
	if err != nil {
		return err
	}
	typ := mime.TypeByExtension(ext)
	if typ == "" {
		typ = "application/octet-stream"
	}
	if s.config.XAccel {
		serveHeaders(w, typ, fi)
		w.Header().Set("X-Accel-Redirect", path.Join(s.config.XAccelPath, hash))
	} else {
		p := s.pathTo(hash)
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		serveHeaders(w, typ, fi)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, req, hash, st.ModTime(), f)
	}
	return nil
}

func main() {
	var (
		addr       = flag.String("addr", "127.0.0.1:9111", "address")
		configPath = flag.String("config", "config.json", "configuration path")
		storePath  = flag.String("store", "store", "store path")
	)
	l := log.New(os.Stderr, "", log.LstdFlags)
	flag.Parse()
	c, err := parseConfig(*configPath)
	if err != nil {
		l.Fatal(err)
	}
	fh, err := newFileHost(*storePath, c, l)
	if err != nil {
		l.Fatal(err)
	}
	srv := &http.Server{
		Addr:         *addr,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      fh,
	}
	l.Fatal(srv.ListenAndServe())
}
