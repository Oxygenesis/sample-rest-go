# GO - Rest - Example

Below are some best practices for developing web applications - rest / Representational State Transfer
in Go, accompanied by examples.

## 1. Use a Structured Directory Layout

Adopt a directory structure such as the commonly used MVC (Model-View-Controller).

## 2. Use a Popular Framework

While the Go standard library is powerful, frameworks like Gin, Echo, or Chi can simplify things.

## 3. Use Middleware for Cross-Cutting Concerns

```go
r := gin.Default() 
r.Use(loggingMiddleware)
```
## 4. Model Binding and Validation
```
type UserInput struct {
    Name  string `form:"name" json:"name" binding:"required"`
    Age   int    `form:"age" json:"age" binding:"gte=0"`
}

func CreateUser(c *gin.Context) {
    var input UserInput
    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
}
```
## 5. Use HTTP Status Codes Properly
```
200 OK for successful GET and PUT.
201 Created for successful POST.
204 No Content for successful DELETE.
400 Bad Request for invalid request.
404 Not Found for missing resources.
500 Internal Server Error for server faults.
```
6. Handle Errors Gracefully
```
if err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
    return
}
```
## 7. Use Dependency Injection

This can be achieved using packages like wire or by manually passing dependencies.

## 8. Pagination

Always paginate results that can grow over time. Use query parameters like limit and offset.

## 9. Use JWT or OAuth for Authentication

Libraries like jwt-go can be used for JWT authentication.

## 10. Keep Sensitive Data Out of Logs and Errors

Never log or return sensitive data like passwords or tokens.

## 11. Use Environment Variables for Configuration

Use libraries like viper or envconfig.

## 12. Database Connection Pooling

For SQL databases, the database/sql package provides connection pooling. Ensure you're not opening and closing a connection for every request.

## 13. Rate Limiting

Implement rate limiting to prevent abuse. Middleware options are available in frameworks like Gin.

## 14. Caching

Use caching mechanisms to speed up frequently accessed, but rarely changed, data. Tools like go-cache or Redis can be used.

## 15. Logging

Use structured logging with libraries like logrus or zap.

## 16. Documentation and Versioning

Document your API using tools like Swagger. Adopt versioning for your API, for example, using URI versioning: /v1/users.

## 17. Test

Write unit and integration tests for your API. Use the testing package that comes with Go and other tools like testify.

