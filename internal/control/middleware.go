package control

import (
	"net/http"
	"runtime/debug"
	"time"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (writer *statusWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *statusWriter) Write(data []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(data)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		wrapped := &statusWriter{ResponseWriter: writer}
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("control request panic", "method", request.Method, "path", request.URL.Path, "panic", recovered, "stack", string(debug.Stack()))
				if wrapped.status == 0 {
					writeProblem(wrapped, http.StatusInternalServerError, "internal server error")
				}
			}
			status := wrapped.status
			if status == 0 {
				status = http.StatusOK
			}
			s.logger.Info("control request", "method", request.Method, "path", request.URL.Path, "status", status, "duration_ms", time.Since(started).Milliseconds())
		}()
		next.ServeHTTP(wrapped, request)
	})
}
