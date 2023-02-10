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

var SYDNEY_SECRET = os.Getenv("SYDNEY_SECRET")
var BING_COOKIE = os.Getenv("BING_COOKIE")

func rateLimitHandler(c *gin.Context, info ratelimit.Info) {
	c.JSON(429, gin.H{
		"message": "Too Many Requests",
	})
}

func main() {
	store := ratelimit.InMemoryStore(&ratelimit.InMemoryOptions{
		Rate:  time.Minute,
		Limit: 5,
	})
	mw := ratelimit.RateLimiter(store, &ratelimit.Options{
		ErrorHandler: rateLimitHandler,
		KeyFunc:      func(c *gin.Context) string { return c.GetHeader("Authorization") },
	})

	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.GET("/auth", mw, func(c *gin.Context) {
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
	r.POST("/allow", func(c *gin.Context) {
		// Get headers and look for Authorization
		authHeader := c.GetHeader("Authorization")
		// Check if the token is valid
		if !isAdminToken(authHeader) {
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
	r.Run() // listen and serve on
}

func isAdminToken(authHeader string) bool {
	// Check if the token is valid
	return authHeader == os.Getenv("SYDNEY_SECRET")
}

func isTokenValid(token string) bool {
	// Check if the token is valid
	_, err := security.VerifyToken(token, "")
	return err == nil
}
