// backends/go-gin/main.go
// Test backend for mini-waf — listens on port 33333.
//
// Endpoints:
//   GET  /                catch_all tier
//   GET  /health          health check
//   ANY  /api/echo        echoes method/path/headers/query/body
//   GET  /api/hello       high tier
//   GET  /api/users       high tier
//   POST /login           critical tier
//   GET  /user/:id        high tier
//   GET  /static/test.txt medium tier
package main

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"backend": "gin", "message": "hello from Gin backend"})
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"healthy": true})
	})

	echoHandler := func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)

		headers := make(map[string]string)
		for k, v := range c.Request.Header {
			headers[k] = v[0]
		}

		query := make(map[string]string)
		for k, v := range c.Request.URL.Query() {
			query[k] = v[0]
		}

		c.JSON(http.StatusOK, gin.H{
			"method":  c.Request.Method,
			"path":    c.Request.URL.Path,
			"headers": headers,
			"query":   query,
			"body":    string(body),
		})
	}
	r.Any("/api/echo", echoHandler)

	r.GET("/api/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "hello from Gin"})
	})

	r.GET("/api/users", func(c *gin.Context) {
		c.JSON(http.StatusOK, []gin.H{
			{"id": 1, "name": "Alice", "backend": "gin"},
			{"id": 2, "name": "Bob", "backend": "gin"},
		})
	})

	r.POST("/login", func(c *gin.Context) {
		var data map[string]interface{}
		_ = c.ShouldBindJSON(&data)
		username, _ := data["username"].(string)
		if username == "" {
			username = "unknown"
		}
		c.JSON(http.StatusOK, gin.H{"token": "test-token-gin", "user": username})
	})

	r.GET("/user/:id", func(c *gin.Context) {
		id := c.Param("id")
		c.JSON(http.StatusOK, gin.H{"id": id, "name": "User " + id, "backend": "gin"})
	})

	r.GET("/static/test.txt", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello from static file (Gin backend)\n")
	})

	r.Run("0.0.0.0:33333")
}
