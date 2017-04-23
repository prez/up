package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
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

type config struct {
	ExternalURL string            `json:"external_url"`
	ExtTypes    map[string]string `json:"ext_types"`
	MaxSize     int64             `json:"max_size"`
	Seed        []byte            `json:"seed"`
	Keys        []string          `json:"keys"`
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
	store  *store
	config *config
	logger *log.Logger
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

func detectContentType(r io.Reader, fh *multipart.FileHeader) (string, io.Reader, error) {
	typ := fh.Header.Get("Content-Type")
	ty, _, err := mime.ParseMediaType(typ)
	if err == nil && ty != "application/octet-stream" {
		return typ, r, nil
	}
	_, ext := splitExt(fh.Filename)
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
	typ, r, err := detectContentType(f, fh)
	if err != nil {
		return err
	}
	fi := fileInfo{Name: fixMultipartPath(fh.Filename), From: remoteAddr(req)}
	name, err := s.store.put(r, &fi)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s/%s%s\n",
		s.config.ExternalURL, name, extensionByType(typ))
	return err
}

// validate and splits a path like <hash>.ext
func cleanPath(p string) (string, string) {
	p = strings.TrimLeft(path.Clean(p), "/")
	if strings.ContainsAny(p, "/\\") {
		return "", ""
	}
	return splitExt(p)
}

// escape file name for content-disposition header
var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func (s *fileHost) serveFile(w http.ResponseWriter, req *http.Request) error {
	hash, ext := cleanPath(req.URL.Path)
	if hash == "" {
		return errBadRequest
	}
	f, err := s.store.get(hash)
	if err != nil {
		return err
	}
	defer f.r.Close()
	typ := mime.TypeByExtension(ext)
	if typ == "" {
		typ = "application/octet-stream"
	}
	w.Header().Set("Content-Type", typ)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if n := f.info.Name; n != "" {
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`inline; filename="%s"`, quoteEscaper.Replace(n)))
	}
	http.ServeContent(w, req, hash, f.mtime, f.r)
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
	s, err := openStore(*storePath, c.Seed)
	if err != nil {
		l.Fatal(err)
	}
	srv := &http.Server{
		Addr:         *addr,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      &fileHost{s, c, l},
	}
	l.Fatal(srv.ListenAndServe())
}
