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
	"sync"
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

// fileStore implements a file system backed hashed file store. It uses the
// following director structure:
//
//    db      - key/value database
//    log     - uploader log
//    public/ - public file directory
//
// The database maps hashes to their original file names. The log contains all
// file uploads, their timestamps and the uploaders' IP addresses. The public
// file directory contains uploaded files named after their hashes.
// The file store root is also used for temporary files.
type fileStore struct {
	path    string
	hash    func() hash.Hash
	db      *bolt.DB
	log     io.WriteCloser
	putLock sync.Mutex
}

var filesBucket = []byte("files")

// openFileStore creates and opens a file store using the given hash function
// at the given path.
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
	return &fileStore{p, hash, db, l, sync.Mutex{}}, db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(filesBucket)
		return err
	})
}

func (fs *fileStore) Close() error {
	fs.log.Close()
	return fs.db.Close()
}

// readToTemp reads all data from r into a temporary file in dir and returns
// the file name.
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

// Put adds a file to the file store, storing the name and originator.
func (fs *fileStore) Put(r io.Reader, name, from string) (string, error) {
	// stream content to temporary file while hashing it
	hw := fs.hash()
	r = io.TeeReader(r, hw)
	tempName, err := readToTemp(fs.path, r)
	if err != nil {
		return "", err
	}
	defer os.Remove(tempName)
	hash := base64.RawURLEncoding.EncodeToString(hw.Sum(nil))
	// take uploading lock
	fs.putLock.Lock()
	defer fs.putLock.Unlock()
	// check if file already exists
	if _, err = fs.Get(hash); err != errNotExist {
		return hash, err
	}
	// log uploader ip
	_, err = fmt.Fprintf(fs.log, "%s %q (%s) from %s\n",
		time.Now().Format(time.RFC3339), name, hash, from)
	if err != nil {
		return hash, err
	}
	// set correct mode
	if err := os.Chmod(tempName, 0644); err != nil {
		return "", err
	}
	// move temp file to store
	p := filepath.Join(fs.path, "public", hash)
	if err := os.Rename(tempName, p); err != nil {
		return "", err
	}
	// add to db
	return hash, fs.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(filesBucket).Put([]byte(hash), []byte(name))
	})
}

// Get checks if a given hash exists in the file store and retrieves it's
// original file name.
func (fs *fileStore) Get(hash string) (string, error) {
	b := []byte(nil)
	err := fs.db.View(func(tx *bolt.Tx) error {
		b = tx.Bucket(filesBucket).Get([]byte(hash))
		if b == nil {
			return errNotExist
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return string(b), err
}

// Open opens a file in the file store, given its hash.
func (fs *fileStore) Open(hash string) (http.File, error) {
	return http.Dir(filepath.Join(fs.path, "public")).Open(hash)
}

type config struct {
	ExternalURL string   `json:"external_url"` // External URL (for user facing links)
	MaxSize     int64    `json:"max_size"`     // Maximum upload file size
	Seed        []byte   `json:"seed"`         // File hash seed
	Keys        []string `json:"keys"`         // Authorized uploader keys
	XAccelPath  string   `json:"x_accel_path"` // X-Accel-Redirect support
}

func parseConfig(p string) (*config, error) {
	b, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, err
	}
	c := &config{}
	return c, json.Unmarshal(b, c)
}

// fileHost exposes a fileStore over HTTP, with password based authentication.
type fileHost struct {
	*fileStore
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
	return &fileHost{fs, c, l}, err
}

// attempt to check uploader key safely
func checkKey(k string, keys []string) bool {
	// make sure keys are a sane length
	if len(k) < 20 || len(k) > 100 {
		return false
	}
	for _, b := range keys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(b)) == 1 {
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

// split file name into name and extension
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

// uploadFile handles file upload requests, checking the provided key against
// authorized ones and handling content type detection. The content type is
// used to find a file extension to append to the returned URL, which is used
// by serveFile later.
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
	typ := fh.Header.Get("Content-Type")
	typ, rd, err := detectContentType(f, fh.Filename, typ)
	if err != nil {
		return err
	}
	addr := remoteAddr(r)
	name, err := s.Put(rd, fixMultipartPath(fh.Filename), addr)
	if err != nil {
		return err
	}
	s.logger.Printf("received file %q (%s) (%s) from %s",
		fh.Filename, typ, name, addr)
	_, err = fmt.Fprintf(w, "%s/%s%s\n",
		s.config.ExternalURL, name, extensionByType(typ))
	return err
}

// escape file name for content-disposition header
var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

// serveFile handles file download requests. It uses the file extension from
// the URL to pick a content type to serve the file with, and sends the file's
// original file name (if any) in the Content-Disposition header.
func (s *fileHost) serveFile(w http.ResponseWriter, r *http.Request) error {
	// clean up and validate path
	p := strings.TrimLeft(path.Clean(r.URL.Path), "/")
	// XXX: strictly not necessary because files are opened through http.Dir
	if strings.ContainsAny(p, "/\\") {
		return errNotExist
	}
	hash, ext := splitExt(p)
	if hash == "" {
		return errNotExist
	}
	name, err := s.Get(hash)
	if err != nil {
		return err
	}
	// use file extension from URL to pick a content type
	typ := mime.TypeByExtension(ext)
	if typ == "" {
		// XXX: fall back to extension from original file name?
		typ = "application/octet-stream"
	}
	w.Header().Set("Content-Type", typ)
	if name != "" {
		// send original file name and try to make browsers display content
		// inline
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`inline; filename="%s"`, quoteEscaper.Replace(name)))
	}
	if s.config.XAccelPath != "" {
		// X-Accel-Redirect to configured path. See
		// https://www.nginx.com/resources/wiki/start/topics/examples/x-accel/
		// for details.
		w.Header().Set("X-Accel-Redirect", path.Join(s.config.XAccelPath, hash))
		return nil
	}
	// XXX: should this use modtime, or neither?
	w.Header().Set("ETag", hash)
	f, err := s.Open(hash)
	if err != nil {
		return err
	}
	defer f.Close()
	http.ServeContent(w, r, hash, time.Time{}, f)
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
		s.logger.Printf("%s %s", remoteAddr(r), err)
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
		Addr: *addr,
		// XXX: should set more timeouts
		// ReadTimeout/ReadHeaderTimeout
		// WriteTimeout
		IdleTimeout: 60 * time.Second,
		ErrorLog:    l,
		Handler:     fh,
	}
	// graceful shutdown support
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
