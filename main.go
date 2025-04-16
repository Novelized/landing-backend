package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"novelized/landing/backend/services"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// Logger is a custom logger that includes timestamps and log levels
type Logger struct {
	*log.Logger
}

// NewLogger creates a new logger with the specified prefix
func NewLogger(prefix string) *Logger {
	return &Logger{
		Logger: log.New(os.Stdout, fmt.Sprintf("[%s] ", prefix), log.Ldate|log.Ltime|log.Lshortfile),
	}
}

// Error logs an error message with additional context
func (l *Logger) Error(format string, v ...interface{}) {
	l.Printf("ERROR: "+format, v...)
}

// Info logs an info message
func (l *Logger) Info(format string, v ...interface{}) {
	l.Printf("INFO: "+format, v...)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, v ...interface{}) {
	l.Printf("DEBUG: "+format, v...)
}

// runMigrations executes all SQL migration files in the migrations directory
func runMigrations(db *sql.DB, logger *Logger) error {
	logger.Info("Running database migrations...")

	// Start a transaction for all migrations
	tx, err := db.Begin()
	if err != nil {
		logger.Error("Failed to start transaction for migrations: %v", err)
		return err
	}

	// Create migrations table if it doesn't exist
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS migrations (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		logger.Error("Failed to create migrations table: %v", err)
		tx.Rollback()
		return err
	}

	// Get list of applied migrations
	rows, err := tx.Query("SELECT name FROM migrations ORDER BY id")
	if err != nil {
		logger.Error("Failed to query applied migrations: %v", err)
		tx.Rollback()
		return err
	}
	defer rows.Close()

	appliedMigrations := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			logger.Error("Failed to scan migration name: %v", err)
			tx.Rollback()
			return err
		}
		appliedMigrations[name] = true
	}

	// Get list of migration files
	files, err := ioutil.ReadDir("migrations")
	if err != nil {
		logger.Error("Failed to read migrations directory: %v", err)
		tx.Rollback()
		return err
	}

	// Sort files by name to ensure they're applied in order
	var migrationFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".sql") {
			migrationFiles = append(migrationFiles, file.Name())
		}
	}
	sort.Strings(migrationFiles)

	// Apply each migration that hasn't been applied yet
	for _, file := range migrationFiles {
		if !appliedMigrations[file] {
			logger.Info("Applying migration: %s", file)

			// Read migration file
			content, err := ioutil.ReadFile(filepath.Join("migrations", file))
			if err != nil {
				logger.Error("Failed to read migration file %s: %v", file, err)
				tx.Rollback()
				return err
			}

			// Execute migration
			_, err = tx.Exec(string(content))
			if err != nil {
				logger.Error("Failed to apply migration %s: %v", file, err)
				tx.Rollback()
				return err
			}

			// Record migration as applied
			_, err = tx.Exec("INSERT INTO migrations (name) VALUES ($1)", file)
			if err != nil {
				logger.Error("Failed to record migration %s as applied: %v", file, err)
				tx.Rollback()
				return err
			}

			logger.Info("Successfully applied migration: %s", file)
		} else {
			logger.Debug("Migration already applied: %s", file)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		logger.Error("Failed to commit migration transaction: %v", err)
		return err
	}

	logger.Info("All migrations applied successfully")
	return nil
}

type HealthResponse struct {
	Status    string `json:"status"`
	Database  string `json:"database"`
	SMTP      string `json:"smtp"`
	Timestamp string `json:"timestamp"`
	Uptime    string `json:"uptime"`
}

var startTime = time.Now()

// checkSMTPConnection tests the SMTP connection
func checkSMTPConnection() error {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		return fmt.Errorf("SMTP configuration missing")
	}

	// Create a timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a channel to handle the connection test
	done := make(chan error, 1)

	go func() {
		// Set up TLS configuration
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         smtpHost,
		}

		// Connect to the SMTP server with TLS
		conn, err := tls.Dial("tcp", smtpHost+":"+smtpPort, tlsConfig)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		// Create a new SMTP client
		client, err := smtp.NewClient(conn, smtpHost)
		if err != nil {
			done <- err
			return
		}
		defer client.Close()

		// Authenticate
		auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
		if err := client.Auth(auth); err != nil {
			done <- err
			return
		}

		done <- nil
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("SMTP connection timeout")
	}
}

type EmailSignup struct {
	Name  string `json:"name" form:"name"`
	Email string `json:"email" form:"email"`
}

type APIInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Endpoints   []struct {
		Path        string `json:"path"`
		Method      string `json:"method"`
		Description string `json:"description"`
	} `json:"endpoints"`
}

// generateVerificationToken creates a random token for email verification
func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// RequestLogger middleware logs details about each request
func RequestLogger(logger *Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Start timer
		start := time.Now()

		// Get request details
		method := c.Method()
		path := c.Path()
		ip := c.IP()
		userAgent := c.Get("User-Agent")

		// Log request
		logger.Info("Request received: %s %s from %s (User-Agent: %s)", method, path, ip, userAgent)

		// Process request
		err := c.Next()

		// Calculate duration
		duration := time.Since(start)

		// Get response status
		status := c.Response().StatusCode()

		// Log response
		if err != nil {
			logger.Error("Request failed: %s %s - Status: %d - Duration: %v - Error: %v",
				method, path, status, duration, err)
			return err
		}

		logger.Info("Request completed: %s %s - Status: %d - Duration: %v",
			method, path, status, duration)

		return nil
	}
}

// sendVerificationEmail sends a verification email to the user
func sendVerificationEmail(name, email, verificationURL string, logger *Logger, emailService *services.EmailService) error {
	from := os.Getenv("SMTP_FROM")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	// Log SMTP configuration (without sensitive data)
	logger.Debug("SMTP Configuration: host=%s, port=%s, from=%s, user=%s",
		smtpHost, smtpPort, from, smtpUser)

	// Validate SMTP configuration
	if from == "" || smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		logger.Error("Missing SMTP configuration: from=%s, host=%s, port=%s, user=%s, pass=%s",
			from, smtpHost, smtpPort, smtpUser, smtpPass != "")
		return fmt.Errorf("missing SMTP configuration")
	}

	// Create the email message
	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:3000" // Default to localhost if not set
	}

	// Generate HTML content using the email service
	htmlBody, err := emailService.GenerateVerificationEmail(name, email, verificationURL)
	if err != nil {
		logger.Error("Failed to generate email template: %v", err)
		return fmt.Errorf("failed to generate email template: %w", err)
	}

	// Create plain text version for email clients that don't support HTML
	plainTextBody := fmt.Sprintf(`Hello %s,

Thank you for signing up for Novelized updates! We're excited to have you join our community.

To complete your signup and start receiving updates, please verify your email address by clicking the link below:

%s

If you didn't request this signup, you can safely ignore this email.

Best regards,
The Novelized Team

© 2025 Novelized. All rights reserved.`, name, verificationURL)

	// Create MIME message
	msg := fmt.Sprintf("To: %s\r\n"+
		"From: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: multipart/alternative; boundary=boundary123\r\n"+
		"\r\n"+
		"--boundary123\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n"+
		"\r\n"+
		"--boundary123\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n"+
		"\r\n"+
		"--boundary123--\r\n", email, from, "Verify your Novelized signup", plainTextBody, htmlBody)

	logger.Debug("Preparing to send verification email to %s from %s via %s:%s", email, from, smtpHost, smtpPort)

	// Log email details (without sensitive information)
	logger.Info("Sending verification email: to=%s, subject=%s, verification_url=%s",
		email, "Verify your Novelized signup", verificationURL)

	// Set up TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         smtpHost,
	}

	// Create a channel to handle timeout
	done := make(chan error, 1)

	// Start a goroutine to send the email
	go func() {
		// Connect to the SMTP server with TLS
		logger.Debug("Connecting to SMTP server %s:%s with TLS", smtpHost, smtpPort)

		// For port 465, we need to use TLS from the start
		conn, err := tls.Dial("tcp", smtpHost+":"+smtpPort, tlsConfig)
		if err != nil {
			logger.Error("Failed to establish TLS connection to SMTP server: %v", err)
			done <- fmt.Errorf("TLS connection failed: %w", err)
			return
		}
		defer conn.Close()

		// Create a new SMTP client
		client, err := smtp.NewClient(conn, smtpHost)
		if err != nil {
			logger.Error("Failed to create SMTP client: %v", err)
			done <- fmt.Errorf("SMTP client creation failed: %w", err)
			return
		}
		defer client.Close()

		// Authenticate
		auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
		if err := client.Auth(auth); err != nil {
			logger.Error("SMTP authentication failed: %v", err)
			done <- fmt.Errorf("SMTP authentication failed: %w", err)
			return
		}

		// Set the sender
		if err := client.Mail(from); err != nil {
			logger.Error("Failed to set sender: %v", err)
			done <- fmt.Errorf("setting sender failed: %w", err)
			return
		}

		// Add the recipient
		if err := client.Rcpt(email); err != nil {
			logger.Error("Failed to add recipient: %v", err)
			done <- fmt.Errorf("adding recipient failed: %w", err)
			return
		}

		// Send the email body
		w, err := client.Data()
		if err != nil {
			logger.Error("Failed to create data writer: %v", err)
			done <- fmt.Errorf("creating data writer failed: %w", err)
			return
		}

		_, err = w.Write([]byte(msg))
		if err != nil {
			logger.Error("Failed to write email data: %v", err)
			done <- fmt.Errorf("writing email data failed: %w", err)
			return
		}

		err = w.Close()
		if err != nil {
			logger.Error("Failed to close data writer: %v", err)
			done <- fmt.Errorf("closing data writer failed: %w", err)
			return
		}

		// Success
		done <- nil
	}()

	// Wait for the email to be sent or timeout
	select {
	case err := <-done:
		if err != nil {
			logger.Error("Failed to send verification email to %s: %v", email, err)
			return err
		}
	case <-time.After(15 * time.Second):
		logger.Error("SMTP operation timed out after 15 seconds")
		return fmt.Errorf("SMTP operation timed out")
	}

	logger.Info("Verification email sent successfully to %s", email)
	return nil
}

func main() {
	// Initialize logger
	logger := NewLogger("Novelized")
	logger.Info("Starting Novelized API server")

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		logger.Info("No .env file found, using environment variables")
	}

	// Get database connection string and encryption key from environment
	dbConnStr := os.Getenv("DATABASE_URL")
	if dbConnStr == "" {
		dbConnStr = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
		logger.Info("Using default database connection string")
	}

	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		logger.Error("ENCRYPTION_KEY environment variable is required")
		log.Fatal("ENCRYPTION_KEY environment variable is required")
	}

	// Initialize database connection
	logger.Info("Connecting to database...")
	db, err := sql.Open("postgres", dbConnStr)
	if err != nil {
		logger.Error("Error connecting to the database: %v", err)
		log.Fatalf("Error connecting to the database: %v", err)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		logger.Error("Error pinging database: %v", err)
		log.Fatalf("Error pinging database: %v", err)
	}
	logger.Info("Database connection established successfully")

	// Set the encryption key in the database session
	_, err = db.Exec("SELECT set_config('app.encryption_key', $1, false)", encryptionKey)
	if err != nil {
		logger.Error("Error setting encryption key: %v", err)
		log.Fatalf("Error setting encryption key: %v", err)
	}
	logger.Info("Encryption key set in database session")

	// Run database migrations
	if err := runMigrations(db, logger); err != nil {
		logger.Error("Failed to run migrations: %v", err)
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize email service
	appURL := os.Getenv("APP_URL")
	if appURL == "" {
		appURL = "http://localhost:3000" // Default to localhost if not set
	}
	emailService := services.NewEmailService(
		"templates/email.html",
		appURL,
	)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "Novelized Landing Backend",
	})

	// Add rate limiting middleware
	app.Use(limiter.New(limiter.Config{
		Max:        100,             // Maximum number of requests
		Expiration: 1 * time.Minute, // Time window
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP() // Rate limit by IP
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests, please try again later",
			})
		},
	}))

	// Add CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins:     os.Getenv("ALLOWED_ORIGINS"), // Comma-separated list of allowed origins
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH",
		AllowHeaders:     "Origin, Content-Type, Accept",
		AllowCredentials: true,
		MaxAge:           12 * 60 * 60, // 12 hours in seconds
	}))

	// Add structured logging middleware
	app.Use(func(c *fiber.Ctx) error {
		start := time.Now()

		// Log request details
		logger.Info("Request started: %s %s from %s", c.Method(), c.Path(), c.IP())

		// Validate request size
		if len(c.Body()) > 1024*1024 { // 1MB limit
			logger.Error("Request too large: %s %s from %s", c.Method(), c.Path(), c.IP())
			return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{
				"error": "Request body too large",
			})
		}

		// Process request
		err := c.Next()

		// Log response details
		latency := time.Since(start)
		status := c.Response().StatusCode()

		if err != nil {
			logger.Error("Request failed: %s %s - Status: %d - Latency: %v - Error: %v",
				c.Method(), c.Path(), status, latency, err)
		} else {
			logger.Info("Request completed: %s %s - Status: %d - Latency: %v",
				c.Method(), c.Path(), status, latency)
		}

		return err
	})

	// Add request logging middleware
	app.Use(RequestLogger(logger))

	// Serve static files using Fiber's static middleware
	app.Static("/static", "./static", fiber.Static{
		Compress:      true,
		ByteRange:     true,
		Browse:        false,
		Index:         "",
		CacheDuration: 24 * time.Hour,
		MaxAge:        31536000, // 1 year
	})

	// Index route
	app.Get("/", func(c *fiber.Ctx) error {
		logger.Debug("API info requested")
		info := APIInfo{
			Name:        "Novelized API",
			Description: "The backend API for Novelized - The Next Generation Storytelling Platform",
			Version:     "1.0.0",
			Endpoints: []struct {
				Path        string `json:"path"`
				Method      string `json:"method"`
				Description string `json:"description"`
			}{
				{
					Path:        "/",
					Method:      "GET",
					Description: "API information and available endpoints",
				},
				{
					Path:        "/health",
					Method:      "GET",
					Description: "Health check endpoint for API and database status",
				},
				{
					Path:        "/signup",
					Method:      "POST",
					Description: "Sign up for Novelized launch updates and development news",
				},
				{
					Path:        "/verify",
					Method:      "GET",
					Description: "Verify email address",
				},
			},
		}
		return c.JSON(info)
	})

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		logger.Debug("Health check requested")
		response := HealthResponse{
			Status:    "ok",
			Timestamp: time.Now().Format(time.RFC3339),
			Uptime:    time.Since(startTime).String(),
		}

		// Check database connection
		err := db.Ping()
		if err != nil {
			logger.Error("Database health check failed: %v", err)
			response.Database = "error"
			response.Status = "degraded"
		} else {
			response.Database = "ok"
		}

		// Check SMTP connection
		err = checkSMTPConnection()
		if err != nil {
			logger.Error("SMTP health check failed: %v", err)
			response.SMTP = "error"
			response.Status = "degraded"
		} else {
			response.SMTP = "ok"
		}

		return c.JSON(response)
	})

	// Email signup endpoint
	app.Post("/signup", func(c *fiber.Ctx) error {
		logger.Debug("Signup request received")

		// Log the raw request body for debugging
		rawBody := string(c.Body())
		logger.Debug("Raw request body: %s", rawBody)

		var signup EmailSignup
		if err := c.BodyParser(&signup); err != nil {
			logger.Error("Invalid request body: %v", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		// Log the parsed data for debugging
		logger.Debug("Parsed signup data: name=%s, email=%s", signup.Name, signup.Email)

		// Ensure values are actual strings and not JSON objects or [object Object]
		if strings.Contains(signup.Name, "[object Object]") || strings.Contains(signup.Email, "[object Object]") {
			logger.Error("Invalid data format: received [object Object] values")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid data format. Please ensure you're sending proper string values.",
			})
		}

		// Trim values and check for empty values (that might be stringified objects)
		signup.Name = strings.TrimSpace(signup.Name)
		signup.Email = strings.TrimSpace(signup.Email)

		// Basic validation
		if signup.Email == "" || signup.Name == "" {
			logger.Error("Missing required fields: name=%s, email=%s", signup.Name, signup.Email)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Both name and email are required",
			})
		}

		// Validate email format
		if !strings.Contains(signup.Email, "@") {
			logger.Error("Invalid email format: missing '@' symbol in %s", signup.Email)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid email format: missing '@' symbol",
			})
		}

		// Validate email format using a simple regex
		emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		if !emailRegex.MatchString(signup.Email) {
			logger.Error("Invalid email format: %s", signup.Email)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid email format: please enter a valid email address",
			})
		}

		// Verify database connection
		if err := db.Ping(); err != nil {
			logger.Error("Database connection error before signup: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Database connection error",
			})
		}

		// Verify encryption key is set
		var encKeySet string
		err := db.QueryRow("SELECT current_setting('app.encryption_key')").Scan(&encKeySet)
		if err != nil || encKeySet == "" {
			logger.Error("Encryption key not set or error checking: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Encryption configuration error",
			})
		}

		// Generate verification token
		token, err := generateVerificationToken()
		if err != nil {
			logger.Error("Failed to generate verification token: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to generate verification token",
			})
		}
		logger.Debug("Verification token generated successfully: %s", token)

		// Start a transaction for the signup process
		tx, err := db.Begin()
		if err != nil {
			logger.Error("Failed to start transaction: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Database error",
			})
		}
		defer tx.Rollback() // Will be ignored if transaction is committed

		// Verify table exists
		var tableExists bool
		err = tx.QueryRow(`
			SELECT EXISTS (
				SELECT FROM information_schema.tables 
				WHERE table_schema = 'public' 
				AND table_name = 'email_signups'
			)
		`).Scan(&tableExists)
		if err != nil {
			logger.Error("Error checking if table exists: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Database error",
			})
		}
		if !tableExists {
			logger.Error("email_signups table does not exist")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Database setup error",
			})
		}

		// Insert encrypted data into database
		logger.Debug("Inserting signup data into database: name=%s, email=%s, token=%s", signup.Name, signup.Email, token)

		// Use direct SQL with parameters to ensure proper handling
		_, err = tx.Exec(`
			INSERT INTO email_signups (name, email, verification_token, verification_sent_at)
			VALUES (
				encrypt_data($1, current_setting('app.encryption_key')),
				encrypt_data($2, current_setting('app.encryption_key')),
				encrypt_data($3, current_setting('app.encryption_key')),
				CURRENT_TIMESTAMP
			)
		`, signup.Name, signup.Email, token)

		if err != nil {
			// Check if it's a duplicate email error
			if err.Error() == "pq: duplicate key value violates unique constraint \"idx_email_signups_email\"" {
				logger.Error("Duplicate email signup attempt: %s", signup.Email)
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{
					"error": "Email already registered",
				})
			}
			logger.Error("Database error during signup: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to save signup information",
			})
		}

		// Commit the transaction
		if err = tx.Commit(); err != nil {
			logger.Error("Failed to commit transaction: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to save signup information",
			})
		}
		logger.Info("Signup data saved to database successfully")

		// Send verification email
		logger.Debug("Preparing to send verification email to %s", signup.Email)
		err = sendVerificationEmail(signup.Name, signup.Email, fmt.Sprintf("%s/verify?token=%s", appURL, token), logger, emailService)
		if err != nil {
			logger.Error("Failed to send verification email to %s: %v", signup.Email, err)
			// Continue anyway, as the signup was successful
		} else {
			logger.Info("Verification email sent successfully to %s", signup.Email)
		}

		logger.Info("Signup process completed successfully for %s", signup.Email)
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message": "Successfully signed up! Please check your email to verify your address.",
		})
	})

	// Email verification endpoint
	app.Get("/verify", func(c *fiber.Ctx) error {
		token := c.Query("token")
		logger.Debug("Verification request received for token: %s", token)

		if token == "" {
			logger.Error("Verification token is missing")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Verification token is required",
			})
		}

		// Update the user's verification status by comparing the plaintext token
		// with the decrypted token stored in the database.
		logger.Debug("Updating verification status in database for token: %s", token)
		result, err := db.Exec(`
			UPDATE email_signups
			SET is_verified = true,
				verified_at = CURRENT_TIMESTAMP,
				verification_token = NULL -- Clear the token once verified
			WHERE decrypt_data(verification_token, current_setting('app.encryption_key')) = $1
			AND is_verified = false
		`, token)

		if err != nil {
			// Check for specific decryption errors
			if strings.Contains(err.Error(), "pgp: invalid data") || strings.Contains(err.Error(), "invalid key") {
				logger.Error("Token decryption failed for token %s: %v", token, err)
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "Invalid or corrupted verification token",
				})
			}
			logger.Error("Database error during verification for token %s: %v", token, err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to verify email",
			})
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			logger.Error("Error getting rows affected for token %s: %v", token, err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to verify email",
			})
		}

		if rowsAffected == 0 {
			logger.Error("Invalid or expired verification token: %s", token)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid or expired verification token",
			})
		}

		logger.Info("Email verified successfully for token: %s", token)
		return c.JSON(fiber.Map{
			"message": "Email verified successfully! Thank you for signing up for Novelized updates.",
		})
	})

	// Test endpoint
	app.Get("/test", func(c *fiber.Ctx) error {
		logger.Debug("Test endpoint called")
		return c.JSON(fiber.Map{
			"status":    "ok",
			"message":   "Server is responding",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	logger.Info("Server starting on port %s", port)
	log.Fatal(app.Listen(":" + port))
}
