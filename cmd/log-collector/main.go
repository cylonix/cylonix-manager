package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/klauspost/compress/zstd"
	"tailscale.com/types/logid"
)

const (
	defaultPort     = "8080"
	defaultDataDir  = "./data"
	maxLogSizeBytes = 10 * 1024 * 1024
	bufferSize      = 32 * 1024
)

var collectionNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

type serverConfig struct {
	Port    string
	DataDir string
}

// Logs are written to the public log ID filename within a collection directory.
// If the log file exceeds maxLogSizeBytes, it is rotated by renaming the
// existing file to filename.log.1 and starting a new file.
// Request needs to provide a private log ID to write to the corresponding
// public log ID file. To avoid leaking information, the private log ID is never
// stored or logged on the server side. Only the client has knowledge of it.
// For reading the log file, requesters can use the public log ID derived
// from the private log ID. The public log ID is shared by the server and
// administrators of the network can find it on the machine's host information.

type logResponse struct {
	Collection string `json:"collection"`
	LogID      string `json:"logId"`
	Bytes      int64  `json:"bytes"`
	CopiedTo   string `json:"copiedTo,omitempty"`
	Copied     bool   `json:"copied"`
}

func main() {
	cfg := serverConfig{
		Port:    getEnv("PORT", defaultPort),
		DataDir: getEnv("DATA_DIR", defaultDataDir),
	}

	router := chi.NewRouter()
	router.Post("/log/c/{collection}/{logUUID}", logHandler(cfg))

	addr := ":" + cfg.Port
	log.Printf("log-collector listening on %s", addr)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func logHandler(cfg serverConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		collection := chi.URLParam(r, "collection")
		logID := chi.URLParam(r, "logUUID")
		if err := validateCollection(collection); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var privateLogID logid.PrivateID
		if err := privateLogID.UnmarshalText([]byte(logID)); err != nil {
			http.Error(w, "invalid log id", http.StatusBadRequest)
			return
		}

		copyTo := strings.TrimSpace(r.URL.Query().Get("copyTo"))
		var privateCopyToLogID logid.PrivateID
		if copyTo != "" {
			if err := privateCopyToLogID.UnmarshalText([]byte(copyTo)); err != nil {
				http.Error(w, "invalid copyTo log id", http.StatusBadRequest)
				return
			}
		}

		reader, err := decodeBody(r)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errUnsupportedEncoding) {
				status = http.StatusUnsupportedMediaType
			}
			http.Error(w, err.Error(), status)
			return
		}
		defer func() {
			if closer, ok := reader.(io.Closer); ok {
				_ = closer.Close()
			}
		}()

		if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
			http.Error(w, "failed to create data dir", http.StatusInternalServerError)
			return
		}

		tmpFile, err := os.CreateTemp(cfg.DataDir, "logpayload-*")
		if err != nil {
			http.Error(w, "failed to create temp file", http.StatusInternalServerError)
			return
		}
		tmpPath := tmpFile.Name()
		defer func() {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}()

		if _, err := io.Copy(tmpFile, reader); err != nil {
			http.Error(w, "failed to read log payload", http.StatusBadRequest)
			return
		}

		logDir := filepath.Join(cfg.DataDir, collection)
		primaryPath := filepath.Join(logDir, privateLogID.Public().String())
		bytesWritten, err := appendWithRotation(primaryPath, tmpPath)
		if err != nil {
			http.Error(w, "failed to write log", http.StatusInternalServerError)
			return
		}

		copied := false
		if copyTo != "" {
			copyPath := filepath.Join(logDir, privateCopyToLogID.Public().String())
			if _, err := appendWithRotation(copyPath, tmpPath); err != nil {
				http.Error(w, "failed to write copy log", http.StatusInternalServerError)
				return
			}
			copied = true
		}

		resp := logResponse{
			Collection: collection,
			LogID:      privateLogID.String(),
			Bytes:      bytesWritten,
			CopiedTo:   privateCopyToLogID.String(),
			Copied:     copied,
		}
		log.Printf("Received log: collection=%s logID=%s bytes=%d copied=%v",
			collection, privateLogID.Public().String(), bytesWritten, copied)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func appendWithRotation(path string, payloadPath string) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}

	payloadFile, err := os.Open(payloadPath)
	if err != nil {
		return 0, err
	}
	defer payloadFile.Close()

	return appendStreamWithRotation(path, payloadFile)
}

func appendStreamWithRotation(path string, src io.Reader) (int64, error) {
	var (
		currentFile *os.File
		currentSize int64
		total       int64
	)

	openFile := func() error {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		currentFile = file
		return nil
	}

	closeFile := func() {
		if currentFile != nil {
			_ = currentFile.Close()
			currentFile = nil
		}
	}

	rotate := func() error {
		closeFile()
		backupPath := path + ".1"
		if _, err := os.Stat(path); err == nil {
			_ = os.Remove(backupPath)
			if err := os.Rename(path, backupPath); err != nil {
				return err
			}
		}
		currentSize = 0
		return openFile()
	}

	if info, err := os.Stat(path); err == nil {
		currentSize = info.Size()
	}

	if currentSize >= maxLogSizeBytes {
		if err := rotate(); err != nil {
			return total, err
		}
	} else if err := openFile(); err != nil {
		return total, err
	}
	defer closeFile()

	buffer := make([]byte, bufferSize)
	for {
		n, readErr := src.Read(buffer)
		if n > 0 {
			written := 0
			for written < n {
				if currentSize >= maxLogSizeBytes {
					if err := rotate(); err != nil {
						return total, err
					}
				}

				space := maxLogSizeBytes - currentSize
				if space <= 0 {
					continue
				}

				chunk := int64(n - written)
				if chunk > space {
					chunk = space
				}

				count, err := currentFile.Write(buffer[written : written+int(chunk)])
				if err != nil {
					return total, err
				}
				if count == 0 {
					return total, io.ErrShortWrite
				}

				written += count
				currentSize += int64(count)
				total += int64(count)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return total, readErr
		}
	}

	return total, nil
}

var errUnsupportedEncoding = errors.New("unsupported content-encoding")

func decodeBody(r *http.Request) (io.Reader, error) {
	encoding := strings.TrimSpace(r.Header.Get("Content-Encoding"))
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		return r.Body, nil
	}

	encodings := strings.Split(encoding, ",")
	for _, value := range encodings {
		if strings.EqualFold(strings.TrimSpace(value), "zstd") {
			decoder, err := zstd.NewReader(r.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to init zstd decoder: %w", err)
			}
			return decoder, nil
		}
	}

	return nil, errUnsupportedEncoding
}

func validateCollection(collection string) error {
	if collection == "" {
		return errors.New("collection name is required")
	}
	if !collectionNamePattern.MatchString(collection) {
		return errors.New("collection name contains invalid characters")
	}
	return nil
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
