package main

import (
	"bytes"
	"context"
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
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"
)

var extOverride = map[string]string{
	"image/gif":                ".gif",
	"image/jpeg":               ".jpeg",
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

type fileInfo struct{ Name, From string }

var filesBucket = []byte("files")

type fileStore struct {
	path string
	hash func() hash.Hash
	db   *bolt.DB
	log  io.Writer
}

func openFileStore(p string, hash func() hash.Hash) (*fileStore, error) {
	if err := os.MkdirAll(filepath.Join(p, "public"), 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(p, "db"),
		0600, &bolt.Options{Timeout: time.Millisecond})
	if err != nil {
		return nil, err
	}
	l, err := os.OpenFile(filepath.Join(p, "log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &fileStore{p, hash, db, l}, db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(filesBucket)
		return err
	})
}

func (fs *fileStore) Close() error { return fs.db.Close() }

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

var b64 = base64.RawURLEncoding.EncodeToString

func (fs *fileStore) Put(r io.Reader, fi *fileInfo) (string, error) {
	hw := fs.hash()
	r = io.TeeReader(r, hw)
	// write to temp file
	tempName, err := readToTemp(fs.path, r)
	if err != nil {
		return "", err
	}
	// clean up on errors
	defer os.Remove(tempName)
	hash := b64(hw.Sum(nil))
	exists := false
	err = fs.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(filesBucket)
		if b.Get([]byte(hash)) != nil {
			exists = true
			return nil
		}
		_, err := fmt.Fprintf(fs.log, "%q (%s) from %s\n",
			fi.Name, hash, fi.From)
		if err != nil {
			return err
		}
		return b.Put([]byte(hash), []byte(fi.Name))
	})
	if exists || err != nil {
		return hash, err
	}
	p := filepath.Join(fs.path, "public", hash)
	if err := os.Rename(tempName, p); err != nil {
		return "", err
	}
	return hash, os.Chmod(p, 0644)
}

func (fs *fileStore) Get(hash string) (http.File, string, error) {
	b := []byte(nil)
	err := fs.db.View(func(tx *bolt.Tx) error {
		b = tx.Bucket(filesBucket).Get([]byte(hash))
		if b == nil {
			return errNotExist
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	f, err := http.Dir(filepath.Join(fs.path, "public")).Open(hash)
	return f, string(b), err
}

type config struct {
	ExternalURL string   `json:"external_url"` // External URL (for links)
	MaxSize     int64    `json:"max_size"`     // Maximum file size
	Seed        []byte   `json:"seed"`         // File hash seed
	Keys        []string `json:"keys"`         // Uploader keys
	XAccelPath  string   `json:"x_accel_path"` // Enable X-Accel-Redirect
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
	fileStore
	config *config
	logger *log.Logger
}

func seededHasher(seed []byte) func() hash.Hash {
	return func() hash.Hash { hw := sha256.New(); hw.Write(seed); return hw }
}

func openFileHost(p string, c *config, l *log.Logger) (*fileHost, error) {
	fs, err := openFileStore(p, seededHasher(c.Seed))
	if err != nil {
		return nil, err
	}
	return &fileHost{*fs, c, l}, err
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
	fi := fileInfo{Name: fixMultipartPath(fh.Filename), From: remoteAddr(r)}
	name, err := s.Put(rd, &fi)
	if err != nil {
		return err
	}
	s.logger.Printf("received file %q (%s) (%s) from %s",
		fh.Filename, typ, name, remoteAddr(r))
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
	f, name, err := s.Get(hash)
	if err != nil {
		return err
	}
	defer f.Close()
	typ := mime.TypeByExtension(ext)
	if typ == "" {
		typ = "application/octet-stream"
	}
	w.Header().Set("Content-Type", typ)
	if name != "" {
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`inline; filename="%s"`, quoteEscaper.Replace(name)))
	}
	if s.config.XAccelPath != "" {
		w.Header().Set("X-Accel-Redirect", path.Join(s.config.XAccelPath, hash))
	} else {
		w.Header().Set("ETag", hash)
		http.ServeContent(w, r, hash, time.Time{}, f)
	}
	return nil
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

func (s *fileHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := errNotExist
	switch r.Method {
	case "POST":
		err = s.uploadFile(w, r)
	case "GET":
		err = s.serveFile(w, r)
	}
	if err != nil {
		s.logger.Printf(`%s %s`, remoteAddr(r), err)
		code, text := toHTTPError(err)
		http.Error(w, text, code)
	}
}

func main() {
	var (
		addr       = flag.String("addr", "127.0.0.1:9111", "address")
		configPath = flag.String("config", "config.json", "configuration path")
		storePath  = flag.String("store", "./store", "store path")
	)
	l := log.New(os.Stderr, "", log.LstdFlags)
	flag.Parse()
	c, err := parseConfig(*configPath)
	if err != nil {
		l.Fatal(err)
	}
	fh, err := openFileHost(*storePath, c, l)
	if err != nil {
		l.Fatal(err)
	}
	defer fh.Close()
	s := &http.Server{
		Addr:        *addr,
		IdleTimeout: 60 * time.Second,
		Handler:     fh,
	}
	die, sig := make(chan struct{}), make(chan os.Signal, 1)
	go func() {
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		if err := s.Shutdown(context.Background()); err != nil {
			log.Println(err)
		}
		close(die)
	}()
	l.Printf("listening on %s", *addr)
	if err := s.ListenAndServe(); err != http.ErrServerClosed {
		log.Println(err)
		return
	}
	<-die
}
