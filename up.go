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
	"hash"
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

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/acme/autocert"
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
	errNotExist     = errors.New("entry does not exist")
	errSizeLimit    = errors.New("size limit exceeded")
)

type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type FileInfo struct {
	Name string `json:"name,omitempty"`
	From string `json:"ip,omitempty"`
}

type FileStore interface {
	Put(r io.Reader, fi *FileInfo) (hash string, err error)
	Get(hash string) (r ReadSeekCloser, fi *FileInfo, err error)
	Close() error
}

var filesBucket = []byte("files")

type fileStore struct {
	path string
	hash func() hash.Hash
	db   *bolt.DB
}

func openFileStore(p string, hasher func() hash.Hash) (FileStore, error) {
	err := os.MkdirAll(filepath.Join(p, "public"), 0700)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(p, "db"),
		0600, &bolt.Options{Timeout: time.Millisecond})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(filesBucket)
		return err
	})
	return &fileStore{p, hasher, db}, err
}

func (fs *fileStore) Close() error {
	return fs.db.Close()
}

func readToTemp(dir string, r io.Reader) (string, error) {
	tf, err := ioutil.TempFile(dir, "tmp-")
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

func (fs *fileStore) pathTo(hash string) string {
	return filepath.Join(fs.path, "public", hash)
}

func b64(b []byte) []byte {
	enc := base64.RawURLEncoding
	encb := make([]byte, enc.EncodedLen(len(b)))
	enc.Encode(encb, b)
	return encb
}

func (fs *fileStore) Put(r io.Reader, fi *FileInfo) (string, error) {
	// concurrently write to hasher
	hw := fs.hash()
	r = io.TeeReader(r, hw)
	// write to temp file
	tempName, err := readToTemp(fs.path, r)
	if err != nil {
		return "", err
	}
	// clean up on error
	defer os.Remove(tempName)
	hash := b64(hw.Sum(nil))
	fib, err := json.Marshal(fi)
	if err != nil {
		return "", err
	}
	exists := false
	err = fs.db.Update(func(tx *bolt.Tx) error {
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
	err = os.Rename(tempName, fs.pathTo(string(hash)))
	if err != nil {
		return "", err
	}
	return string(hash), os.Chmod(fs.pathTo(string(hash)), 0600)
}

func (fs *fileStore) Get(hash string) (ReadSeekCloser, *FileInfo, error) {
	fi := &FileInfo{}
	err := fs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(filesBucket).Get([]byte(hash))
		if b == nil {
			return errNotExist
		}
		return json.Unmarshal(b, fi)
	})
	if err != nil {
		return nil, nil, err
	}
	f, err := http.Dir(filepath.Join(fs.path, "public")).Open(hash)
	return f, fi, err
}

type config struct {
	ExternalURL string   `json:"external_url"` // External URL (for links)
	MaxSize     int64    `json:"max_size"`     // Maximum file size
	Seed        []byte   `json:"seed"`         // File hash seed
	Keys        []string `json:"keys"`         // Uploader keys
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
	FileStore
	tls    bool
	config *config
	logger *log.Logger
}

func seededHasher(seed []byte) func() hash.Hash {
	return func() hash.Hash { hw := sha256.New(); hw.Write(seed); return hw }
}

func openFileHost(p string, tls bool, c *config, l *log.Logger) (*fileHost, error) {
	if len(c.Seed) < 32 {
		return nil, errors.New("seed too short")
	}
	hasher := seededHasher(c.Seed)
	fs, err := openFileStore(p, hasher)
	return &fileHost{fs, tls, c, l}, err
}

func toHTTPError(err error) (int, string) {
	switch {
	case os.IsNotExist(err) || err == errNotExist:
		return 404, "Not Found"
	case os.IsPermission(err) || err == errUnauthorized:
		return 403, "Forbidden"
	case err == errSizeLimit:
		return 413, "Payload Too Large"
	}
	return 500, "Internal Server Error"
}

// attempt to check uploader key safely
func checkKey(k string, keys []string) bool {
	// make sure keys are a sane length
	if len(k) < 20 || len(k) > 100 {
		return false
	}
	for _, b := range keys {
		if len(k) == len(b) && subtle.ConstantTimeCompare([]byte(k), []byte(b)) == 1 {
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
	// try content type
	ty, _, err := mime.ParseMediaType(typ)
	if err == nil && ty != "application/octet-stream" {
		return typ, r, nil
	}
	// try file extension
	_, ext := splitExt(name)
	if typ := mime.TypeByExtension(ext); typ != "" {
		return typ, r, nil
	}
	// fall back to sniffing
	preview := make([]byte, 512)
	n, err := io.ReadFull(r, preview)
	switch {
	case err == io.ErrUnexpectedEOF || err == io.EOF:
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

// XXX: doesn't support X-Forwarded-For
func remoteAddr(req *http.Request) string {
	h := req.Header.Get("X-Real-IP")
	if h == "" {
		h, _, _ = net.SplitHostPort(req.RemoteAddr)
	}
	return h
}

func (s *fileHost) uploadFile(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxSize)
	k := r.FormValue("k")
	if !checkKey(k, s.config.Keys) {
		return errUnauthorized
	}
	if r.ContentLength > s.config.MaxSize {
		return errSizeLimit
	}
	f, fh, err := r.FormFile("f")
	if err != nil {
		return err
	}
	defer f.Close()
	typ, rd, err := detectContentType(f, fh.Filename, fh.Header.Get("Content-Type"))
	if err != nil {
		return err
	}
	fi := FileInfo{Name: fixMultipartPath(fh.Filename), From: remoteAddr(r)}
	name, err := s.Put(rd, &fi)
	if err != nil {
		return err
	}
	s.logger.Printf("received file %q (%s) from %s", fh.Filename, name, remoteAddr(r))
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

func (s *fileHost) serveFile(w http.ResponseWriter, r *http.Request) error {
	hash, ext := cleanPath(r.URL.Path)
	if hash == "" {
		return errNotExist
	}
	f, fi, err := s.Get(hash)
	if err != nil {
		return err
	}
	defer f.Close()
	w.Header().Set("ETag", hash)
	typ := mime.TypeByExtension(ext)
	if typ == "" {
		typ = "application/octet-stream"
	}
	w.Header().Set("Content-Type", typ)
	if n := fi.Name; n != "" {
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`inline; filename="%s"`, quoteEscaper.Replace(n)))
	}
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, hash, time.Time{}, f)
	return nil
}

func (s *fileHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// redirect / to https
	if s.tls && r.TLS == nil && strings.TrimLeft(path.Clean(r.URL.Path), "/") == "" {
		http.Redirect(w, r, "https://"+r.Host, http.StatusMovedPermanently)
		return
	}
	var err error
	switch r.Method {
	case "POST":
		err = s.uploadFile(w, r)
	case "GET":
		err = s.serveFile(w, r)
	default:
		err = errNotExist
	}
	if err != nil {
		s.logger.Printf("%s: %s", remoteAddr(r), err)
		code, text := toHTTPError(err)
		http.Error(w, text, code)
	}
}

func main() {
	var (
		addr       = flag.String("addr", "127.0.0.1:9111", "address")
		tlsAddr    = flag.String("tlsAddr", "", "https address")
		acmeHost   = flag.String("acmehost", "", "acme host name")
		configPath = flag.String("config", "config.json", "configuration path")
		storePath  = flag.String("store", "./store", "store path")
	)
	l := log.New(os.Stderr, "", log.LstdFlags)
	flag.Parse()
	c, err := parseConfig(*configPath)
	if err != nil {
		l.Fatal(err)
	}
	h, err := openFileHost(*storePath, *tlsAddr != "", c, l)
	if err != nil {
		l.Fatal(err)
	}
	defer h.Close()
	if *acmeHost != "" {
		m := &autocert.Manager{
			Cache:      autocert.DirCache(filepath.Join(*storePath, "acme")),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*acmeHost),
		}
		s := &http.Server{
			Addr:        *tlsAddr,
			IdleTimeout: 60 * time.Second,
			TLSConfig:   m.TLSConfig(),
			Handler:     h,
		}
		go func() { l.Fatal(s.ListenAndServeTLS("", "")) }()
	}
	s := &http.Server{
		Addr:        *addr,
		IdleTimeout: 60 * time.Second,
		Handler:     h,
	}
	l.Fatal(s.ListenAndServe())
}
