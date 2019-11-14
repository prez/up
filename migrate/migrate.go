package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

type fileInfo struct {
	Name string `json:"name,omitempty"`
	From string `json:"ip,omitempty"`
}

var filesBucket = []byte("files")

func run() error {
	storePath := flag.String("store", "./store", "store path")
	flag.Parse()
	p := *storePath
	olddb, err := bolt.Open(filepath.Join(p, "db"),
		0600, &bolt.Options{Timeout: time.Millisecond})
	if err != nil {
		return err
	}
	defer olddb.Close()
	newdb, err := bolt.Open(filepath.Join(p, "db2"),
		0600, &bolt.Options{Timeout: time.Millisecond})
	if err != nil {
		return err
	}
	defer newdb.Close()
	l, err := os.OpenFile(filepath.Join(p, "log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer l.Close()
	newdb.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket(filesBucket)
		return err
	})
	return olddb.View(func(tx *bolt.Tx) error {
		return tx.Bucket(filesBucket).ForEach(func(k, v []byte) error {
			fi := fileInfo{}
			err := json.Unmarshal(v, &fi)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(l, "%q (%s) from %s\n",
				fi.Name, string(k), fi.From)
			if err != nil {
				return err
			}
			return newdb.Batch(func(tx *bolt.Tx) error {
				return tx.Bucket(filesBucket).Put(k, []byte(fi.Name))
			})
		})
	})
}

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}
