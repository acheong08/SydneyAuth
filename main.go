package main

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"time"

	ratelimit "github.com/JGLTechnologies/gin-rate-limit"
	"github.com/RunawayVPN/security"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var BING_COOKIE = os.Getenv("BING_COOKIE")
var SYDNEY_AUTH = os.Getenv("SYDNEY_AUTH")

func rateLimitHandler(c *gin.Context, info ratelimit.Info) {
	c.JSON(429, gin.H{
		"message": "Too Many Requests",
	})
}

func main() {
	auth_store := ratelimit.InMemoryStore(&ratelimit.InMemoryOptions{
		Rate:  time.Minute,
		Limit: 5,
	})
	auth_limiter := ratelimit.RateLimiter(auth_store, &ratelimit.Options{
		ErrorHandler: rateLimitHandler,
		KeyFunc:      func(c *gin.Context) string { return c.GetHeader("Authorization") },
	})

	allow_store := ratelimit.InMemoryStore(&ratelimit.InMemoryOptions{
		Rate:  24 * time.Hour,
		Limit: 2,
	})
	allow_limiter := ratelimit.RateLimiter(allow_store, &ratelimit.Options{
		ErrorHandler: rateLimitHandler,
		KeyFunc:      func(c *gin.Context) string { return c.ClientIP() },
	})

	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.GET("/auth", auth_limiter, func(c *gin.Context) {
		// Get headers and look for Authorization
		authHeader := c.GetHeader("Authorization")
		// Check if the token is valid
		if !isTokenValid(authHeader) {
			c.JSON(401, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		// Make HTTP request to https://www.bing.com/turing/conversation/create with cookie
		request := http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "https", Host: "www.bing.com", Path: "/turing/conversation/create"},
		}
		headers := http.Header{
			"accept":          []string{"application/json"},
			"accept-encoding": []string{"gzip, deflate, br"},
			"accept-language": []string{"en-US,en;q=0.9"},
			"content-type":    []string{"application/json"},
			"sec-ch-ua":       []string{"\"Microsoft Edge\";v=\"111\", \"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"111\""},
			"sec-ch-ua-arch":  []string{"\"x86\""}, "sec-ch-ua-bitness": []string{"\"64\""},
			"sec-ch-ua-full-version":      []string{"\"111.0.1652.0\""},
			"sec-ch-ua-full-version-list": []string{"\"Microsoft Edge\";v=\"111.0.1652.0\", \"Not(A:Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"111.0.5551.0\""},
			"sec-ch-ua-mobile":            []string{"?0"}, "sec-ch-ua-model": []string{""}, "sec-ch-ua-platform": []string{"\"Linux\""},
			"sec-ch-ua-platform-version": []string{"\"5.19.0\""},
			"sec-fetch-dest":             []string{"empty"},
			"sec-fetch-mode":             []string{"cors"},
			"sec-fetch-site":             []string{"same-origin"},
			"user-agent":                 []string{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.0.0"},
			"x-ms-client-request-id":     []string{uuid.New().String()}}
		request.Header = headers
		jar, err := cookiejar.New(nil)
		if err != nil {
			c.JSON(500, gin.H{
				"message": "Internal Server Error",
			})
			c.Abort()
			return
		}
		cookie := &http.Cookie{
			Name:  "_U",
			Value: BING_COOKIE,
		}
		jar.SetCookies(&url.URL{Scheme: "https", Host: "www.bing.com"}, []*http.Cookie{cookie})
		request.Header = http.Header{
			"Cookie": []string{"_U=" + BING_COOKIE},
		}
		response, err := http.DefaultClient.Do(&request)
		if err != nil {
			c.JSON(500, gin.H{
				"message": "Internal Server Error",
			})
			c.Abort()
			return
		}
		// Get response JSON
		response_json := make(map[string]interface{})
		err = json.NewDecoder(response.Body).Decode(&response_json)
		if err != nil {
			c.JSON(500, gin.H{
				"message": "Internal Server Error",
			})
			c.Abort()
			return
		}
		// Return response JSON
		c.JSON(200, response_json)

	})
	r.POST("/allow", allow_limiter, func(c *gin.Context) {
		// Check if the token is valid
		if c.GetHeader("Sydney_Auth") != SYDNEY_AUTH {
			c.JSON(401, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		// Generate random UUID
		uuid := uuid.New().String()
		// Create token
		token, err := security.CreateToken(uuid)
		if err != nil {
			c.JSON(500, gin.H{
				"message": "Internal Server Error",
			})
			c.Abort()
			return
		}
		// Return token
		c.JSON(200, gin.H{
			"token": token,
		})

	})
	r.Run("127.0.0.1:8008") // listen and serve on
}

func isTokenValid(token string) bool {
	// Check if the token is valid
	_, err := security.VerifyToken(token, "")
	return err == nil
}
