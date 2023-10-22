// @title User Service API
// @version 1.0
// @description API for managing users.
// @host localhost:8082
// @BasePath /v1
// @schemes http
// @SecurityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/oxygenesis/sample-rest-go/docs"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLog "gorm.io/gorm/logger"
)

type User struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Name string `form:"name" json:"name" binding:"required"`
	Age  int    `form:"age" json:"age" binding:"gte=0"`
}

type LoginInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	once  sync.Once
	db    *gorm.DB
	errDB error
)

var secretKey = "yourSecretKey"
var logger = logrus.New()
var requestCount = make(map[string]int)

func main() {
	// 15. Logging with logrus
	logger.Out = os.Stdout
	logger.SetLevel(logrus.InfoLevel)
	logger.Info("Starting the application...")

	r := gin.Default()

	// Configure zerolog to print human-friendly logs
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// 16. Documentation with Swagger
	docs.SwaggerInfo.BasePath = "/v1"
	url := ginSwagger.URL("/v1/swagger/doc.json") // The url pointing to API definition

	// 16. Versioning
	v1 := r.Group("/v1")
	{
		v1.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, url))
		v1.POST("/login", Login)
		api := v1.Group("/api")
		api.Use(AuthMiddleware(), RateLimitMiddleware(time.Minute, 5))
		{
			api.GET("/users", ListUsers)
			api.POST("/users", CreateUser)
			api.GET("/users/:id", GetUser)
			api.DELETE("/users/:id", DeleteUser)
		}
	}

	getDB()
	srv := &http.Server{
		Addr:    ":8082",
		Handler: r,
	}

	// Running our server in a goroutine so that it doesn't block
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server with a timeout of 5 seconds.
	quit := make(chan os.Signal)
	// kill (no param) default sends syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be caught so don't need to add it here
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("Shutting down server...")

	// The context is used to inform the server it has 5 seconds to finish the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		fmt.Println("Server forced to shutdown:", err)
	}

	fmt.Println("Server exiting")
}

func initDB() {
	var err error
	fmt.Println("Connect to db")

	dsn := "host=db.rest.orb.local user=gorm password=gorm dbname=gorm port=5432 sslmode=disable TimeZone=Asia/Shanghai"

	// Set a timeout of 10 seconds
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err = gorm.Open(
		postgres.Open(dsn), &gorm.Config{
			NowFunc: func() time.Time {
				return time.Now().In(time.UTC)
			},
			Logger: &ZerologGormLogger{},
		},
	)

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		logger.Fatal("Timeout while connecting to the database")
		return
	}

	if err != nil {
		logger.Fatal("Failed to connect to database:", err)
	}

	fmt.Println("Connected to db successfully")
	db.AutoMigrate(&User{})
}

func getDB() *gorm.DB {
	once.Do(initDB)
	return db
}

func RateLimitMiddleware(interval time.Duration, maxRequests int) gin.HandlerFunc {
	return func(c *gin.Context) {
		remoteIP := c.ClientIP()
		if count, exists := requestCount[remoteIP]; exists && count >= maxRequests {
			logger.Warnf("Rate limit exceeded for IP: %s", remoteIP)
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}

		if _, exists := requestCount[remoteIP]; !exists {
			go func() {
				time.Sleep(interval)
				delete(requestCount, remoteIP)
			}()
		}

		requestCount[remoteIP]++
		c.Next()
	}
}

// ListUsers lists all users with pagination
// @Summary List users
// @Description Fetch all users with optional pagination
// @Produce json
// @Param page query int false "Page number"
// @Param limit query int false "Limit"
// @Success 200 {array} User
// @Failure 400 {object} map[string]string "Bad Request"
// @Router /api/users [get]
func ListUsers(c *gin.Context) {
	// 8. Pagination
	page := 0
	if p, _ := c.GetQuery("page"); p != "" {
		fmt.Sscanf(p, "%d", &page)
		page -= 1
	}

	limit := 5
	if l, _ := c.GetQuery("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}

	var users []User
	userDB := getDB()
	userDB.Offset(page * limit).Limit(limit).Find(&users)

	c.JSON(http.StatusOK, users) // 5. 200 status
}

// @Summary Create new user
// @Description Add a new user
// @Accept json
// @Produce json
// @Param input body User true "User Information"
// @Success 201 {object} map[string]string "Successfully created user"
// @Failure 400 {object} map[string]string "Bad Request"
// @Failure 500 {object} map[string]string "Internal Server Error"
// @Router /api/users [post]
func CreateUser(c *gin.Context) {
	var input User
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // 5. 400 status
		return
	}

	userDB := getDB()
	if err := userDB.Create(&input).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"}) // 5. 500 status
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully!", "user": input}) // 5. 201 status
}

// @Summary Get a user by ID
// @Description Fetch a single user by ID
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} User
// @Failure 404 {object} map[string]string "Not Found"
// @Router /api/users/{id} [get]
func GetUser(c *gin.Context) {
	var user User
	userDB := getDB()
	if err := userDB.First(&user, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"}) // 5. 404 status
		return
	}

	c.JSON(http.StatusOK, user) // 5. 200 status
}

// @Summary Delete a user
// @Description Remove a user by ID
// @Param id path int true "User ID"
// @Success 204 "Successfully deleted user"
// @Failure 500 {object} map[string]string "Internal Server Error"
// @Router /api/users/{id} [delete]
func DeleteUser(c *gin.Context) {
	userDB := getDB()
	if err := userDB.Delete(&User{}, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"}) // 5. 500 status
		return
	}

	c.Status(http.StatusNoContent) // 5. 204 status
}

// @Summary Authenticate user and get token
// @Description Verify user credentials and return a JWT
// @Accept json
// @Produce json
// @Param input body LoginInfo true "Login Information"
// @Success 200 {object} map[string]string "Authentication successful"
// @Failure 400 {object} map[string]string "Bad Request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Router /login [post]
func Login(c *gin.Context) {
	var loginInfo LoginInfo
	if err := c.ShouldBindJSON(&loginInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // 5. 400 status
		return
	}

	// This is just a dummy check. In real-world scenarios, you'd be checking against a database, hashed passwords, etc.
	if loginInfo.Username != "admin" || loginInfo.Password != "password" {
		c.JSON(
			http.StatusUnauthorized, gin.H{"error": "Invalid credentials"},
		) // not part of the given codes but should be handled
		return
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256, jwt.MapClaims{
			"username": loginInfo.Username,
		},
	)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"}) // 5. 500 status
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString}) // 5. 200 status
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		token, err := jwt.Parse(
			tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(secretKey), nil
			},
		)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("username", claims["username"])
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
		}
	}
}

type ZerologGormLogger struct {
	level gormLog.LogLevel
}

func (z *ZerologGormLogger) LogMode(level gormLog.LogLevel) gormLog.Interface {
	newLogger := *z
	newLogger.level = level
	return &newLogger
}

func (z ZerologGormLogger) Info(ctx context.Context, s string, i ...interface{}) {
	if z.level <= gormLog.Info {
		log.Ctx(ctx).Info().Msgf(s, i...)
	}
}

func (z ZerologGormLogger) Warn(ctx context.Context, s string, i ...interface{}) {
	if z.level <= gormLog.Warn {
		log.Ctx(ctx).Warn().Msgf(s, i...)
	}
}

func (z ZerologGormLogger) Error(ctx context.Context, s string, i ...interface{}) {
	if z.level <= gormLog.Error {
		log.Ctx(ctx).Error().Msgf(s, i...)
	}
}

func (z ZerologGormLogger) Printf(ctx context.Context, format string, args ...interface{}) {
	log.Ctx(ctx).Info().Msgf(format, args...)
}

func (z ZerologGormLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	elapsed := time.Since(begin)
	msg, _ := fc()
	switch {
	case err != nil:
		log.Ctx(ctx).Error().Err(err).Str("elapsed", elapsed.String()).Msg(msg)
	case elapsed > 200*time.Millisecond:
		// Print slow queries
		log.Ctx(ctx).Warn().Str("elapsed", elapsed.String()).Msg(msg)
	default:
		log.Ctx(ctx).Info().Str("elapsed", elapsed.String()).Msg(msg)
	}
}
