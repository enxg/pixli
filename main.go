package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/client"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/gofiber/template/html/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-querystring/query"
	_ "github.com/joho/godotenv/autoload"
	"github.com/jxskiss/base62"
	"github.com/robfig/cron/v3"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type JWTClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type DeletionKeyClaims struct {
	ShortURL string `json:"short_url"`
	jwt.RegisteredClaims
}

type GHAuthParams struct {
	ClientID     string `url:"client_id"`
	ClientSecret string `url:"client_secret"`
	Code         string `url:"code"`
}

type GHAuthResponse struct {
	AccessToken string `json:"access_token"`
}

type GHUserResponse struct {
	Username string `json:"login"`
	ID       int64  `json:"id"`
}

type IndexData struct {
	Auth             bool
	GithubClientID   string
	TurnstileSiteKey string
	User             User
	UntilMin         string
	UntilMaxEnabled  bool
	UntilMax         string
	Notices          []string
	URLs             []URL
}

type URLListData struct {
	URLs []URL
}

type Settings struct {
	MaxDuration time.Duration
	Admins      map[string]struct{}
}

type ShortenRequest struct {
	URL         string `form:"url"`
	EnableUntil string `form:"enableUntil"`
	Until       string `form:"until"`
	Timezone    string `form:"timezone"`
}

type Counter struct {
	CounterID string `bson:"counter_id"`
	Seq       int64  `bson:"seq"`
}

type URL struct {
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
	Until       time.Time `bson:"until,omitempty" json:"until,omitempty"`
	UserID      string    `bson:"user_id" json:"-"`
	ShortURL    string    `bson:"short_url" json:"short_url"`
	OriginalURL string    `bson:"original_url" json:"original_url"`
	DeletionKey string    `bson:"deletion_key" json:"-"`
}

type User struct {
	ID       string
	Username string
	Admin    bool
}

var UserKey struct{}

func main() {
	ctx := context.Background()

	settings := Settings{}

	ghClientId := os.Getenv("GITHUB_CLIENT_ID")
	ghClientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

	jwtSecret, err := base64.RawStdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to decode JWT secret")
	}

	maxDurationMinutes, err := strconv.Atoi(os.Getenv("PIXLI_MAX_DURATION"))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse PIXLI_MAX_DURATION")
	}

	settings.MaxDuration = time.Duration(maxDurationMinutes) * time.Minute

	settings.Admins = make(map[string]struct{})

	for _, admin := range strings.Split(os.Getenv("PIXLI_ADMINS"), ",") {
		settings.Admins[admin] = struct{}{}
	}

	dbc, _ := mongo.Connect(options.Client().ApplyURI(os.Getenv("DATABASE_URL")))
	defer func() {
		if err := dbc.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()

	dbName := os.Getenv("DATABASE_NAME")
	if dbName == "" {
		dbName = "pixli"
	}

	db := dbc.Database(dbName)
	urlCollection := db.Collection("urls")
	counterCollection := db.Collection("counters")

	var urlCounter Counter
	err = counterCollection.FindOne(ctx, bson.D{{"counter_id", "url"}}).Decode(&urlCounter)
	if errors.Is(err, mongo.ErrNoDocuments) {
		_, err = counterCollection.InsertOne(ctx, Counter{
			CounterID: "url",
			Seq:       0,
		})
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize URL counter")
		}
	} else if err != nil {
		log.Fatal().Err(err).Msg("Failed to get URL counter")
	}

	c := cron.New()
	_, err = c.AddFunc("*/5 * * * *", func() {
		res, err := urlCollection.DeleteMany(ctx, bson.D{{"until", bson.D{{"$lte", time.Now()}}}})
		if err != nil {
			log.Error().Err(err).Msg("Failed to clean up expired URLs")
			return
		}
		if res.DeletedCount > 0 {
			log.Info().Msgf("Cleaned up %d expired URLs", res.DeletedCount)
		}
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to schedule URL cleanup job")
	}
	c.Start()
	defer c.Stop()
	log.Info().Msg("Started URL cleanup cron job")

	cc := client.NewWithClient(&fasthttp.Client{
		ReadBufferSize: 16384,
	})
	cc.SetTimeout(10 * time.Second)
	cc.SetJSONMarshal(sonic.Marshal)
	cc.SetJSONUnmarshal(sonic.Unmarshal)

	engine := html.New("./templates", ".html")

	app := fiber.New(fiber.Config{
		Views: engine,

		JSONDecoder: sonic.Unmarshal,
		JSONEncoder: sonic.Marshal,
	})

	app.Use("/", static.New("./static"))
	app.Use("/", func(c fiber.Ctx) error {
		c.Locals(UserKey, nil)
		tokenString := c.Cookies("TOKEN")

		if tokenString == "" {
			return c.Next()
		}

		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil {
			log.Error().Err(err).Msg("Failed to parse JWT token")
			return c.Next()
		}
		if !token.Valid {
			return c.Next()
		}

		if claims, ok := token.Claims.(*JWTClaims); ok {
			_, isAdmin := settings.Admins[claims.Subject]

			c.Locals(UserKey, User{
				ID:       claims.Subject,
				Username: claims.Username,
				Admin:    isAdmin,
			})
		} else {
			log.Error().Msg("Invalid JWT claims type")
		}

		return c.Next()
	})

	app.Get("/", func(c fiber.Ctx) error {
		logout := fiber.Query[bool](c, "logout")
		if logout {
			c.ClearCookie("TOKEN")
			return c.Render("index", IndexData{
				Auth:           false,
				GithubClientID: ghClientId,
			})
		}

		if user, ok := c.Locals(UserKey).(User); ok {
			return renderAuth(c, ctx, user, settings, urlCollection)
		}

		authCode := c.Query("code")

		if authCode == "" {
			return c.Render("index", IndexData{
				Auth:           false,
				GithubClientID: ghClientId,
			})
		}

		v, _ := query.Values(GHAuthParams{
			ClientID:     ghClientId,
			ClientSecret: ghClientSecret,
			Code:         authCode,
		})
		res, err := cc.Post("https://github.com/login/oauth/access_token?"+v.Encode(), client.Config{
			Header: map[string]string{
				"Accept": "application/json",
			},
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to get access token from GitHub")
			return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
		}
		if res.StatusCode() != fiber.StatusOK {
			log.Error().Msgf("GitHub OAuth failed with status code: %d", res.StatusCode())
			return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
		}

		var resp GHAuthResponse
		err = res.JSON(&resp)
		if err != nil {
			log.Error().Err(err).Msg("Failed to parse GitHub response")
			return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
		}

		res, err = cc.Get("https://api.github.com/user", client.Config{
			Header: map[string]string{
				"Accept":        "application/json",
				"Content-Type":  "application/json",
				"Authorization": "Bearer " + resp.AccessToken,
			},
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to get user info from GitHub")
			return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
		}
		if res.StatusCode() != fiber.StatusOK {
			log.Error().Msgf("GitHub user info request failed with status code: %d", res.StatusCode())
			return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
		}

		var userResp GHUserResponse
		err = res.JSON(&userResp)
		if err != nil {
			log.Error().Err(err).Msg("Failed to parse user info response from GitHub")
			return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
		}

		userId := strconv.FormatInt(userResp.ID, 10)
		claims := JWTClaims{
			Username: userResp.Username,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   userId,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(8 * time.Hour)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			log.Error().Err(err).Msg("Failed to sign JWT token")
			return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
		}

		c.Cookie(&fiber.Cookie{
			Name:     "TOKEN",
			Value:    tokenString,
			Expires:  time.Now().Add(8 * time.Hour),
			HTTPOnly: true,
		})

		_, isAdmin := settings.Admins[userId]

		user := User{
			ID:       userId,
			Username: userResp.Username,
			Admin:    isAdmin,
		}

		return renderAuth(c, ctx, user, settings, urlCollection)
	})

	app.Post("/api/shorten", func(c fiber.Ctx) error {
		user, ok := c.Locals(UserKey).(User)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "unauthorized",
			})
		}

		req := new(ShortenRequest)
		if err := c.Bind().Body(req); err != nil {
			return err
		}

		var counter Counter
		err = counterCollection.
			FindOneAndUpdate(ctx, bson.D{{"counter_id", "url"}}, bson.D{{"$inc", bson.D{{"seq", 1}}}}).
			Decode(&counter)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get and update URL counter")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal_server_error",
			})
		}

		sUrl := string(base62.Encode([]byte(strconv.FormatInt(counter.Seq, 10))))
		delClaims := DeletionKeyClaims{
			ShortURL: sUrl,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  user.ID,
				IssuedAt: jwt.NewNumericDate(time.Now()),
			},
		}
		delToken := jwt.NewWithClaims(jwt.SigningMethodHS256, delClaims)
		delKey, err := delToken.SignedString(jwtSecret)
		if err != nil {
			log.Error().Err(err).Msg("Failed to sign deletion key JWT token")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal_server_error",
			})
		}

		url := URL{
			CreatedAt:   time.Now(),
			UserID:      user.ID,
			ShortURL:    sUrl,
			OriginalURL: req.URL,
			DeletionKey: delKey,
		}

		if settings.MaxDuration != time.Duration(0) && req.EnableUntil != "on" && !user.Admin {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "until_required",
			})
		}

		if req.EnableUntil == "on" {
			tzOffsetMin, err := strconv.ParseInt(req.Timezone, 10, 32)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "invalid_until",
				})
			}
			u, err := time.Parse("2006-01-02T15:04", req.Until)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "invalid_until",
				})
			}

			u = u.Add(time.Duration(tzOffsetMin) * time.Minute)

			if u.Before(time.Now()) {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "invalid_until",
				})
			}
			if settings.MaxDuration != time.Duration(0) && u.Sub(time.Now()) > settings.MaxDuration && !user.Admin {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "until_too_long",
				})
			}
			url.Until = u
		}

		_, err = urlCollection.InsertOne(ctx, url)
		if err != nil {
			log.Error().Err(err).Msg("Failed to insert URL into database")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal_server_error",
			})
		}

		find, err := urlCollection.Find(ctx, bson.D{{"user_id", user.ID}}, options.Find().
			SetSort(bson.D{{"created_at", -1}}).
			SetLimit(10))
		if err != nil {
			log.Error().Err(err).Msg("Failed to find URLs for user")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal_server_error",
			})
		}
		var urls []URL
		if err = find.All(ctx, &urls); err != nil {
			log.Error().Err(err).Msg("Failed to decode URLs for user")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal_server_error",
			})
		}

		return c.Render("url-list", URLListData{
			URLs: urls,
		})
	})

	app.Post("/api/delete/:deletionKey", func(c fiber.Ctx) error {
		delToken, err := jwt.ParseWithClaims(c.Params("deletionKey"), &DeletionKeyClaims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid_deletion_key",
			})
		}
		if !delToken.Valid {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid_deletion_key",
			})
		}

		claims, ok := delToken.Claims.(*DeletionKeyClaims)
		if !ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid_deletion_key",
			})
		}

		var deletedURL URL
		err = urlCollection.FindOneAndDelete(ctx, bson.D{{"short_url", claims.ShortURL}, {"user_id", claims.Subject}}).
			Decode(&deletedURL)
		if errors.Is(err, mongo.ErrNoDocuments) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "not_found",
			})
		}
		if err != nil {
			log.Error().Err(err).Msg("Failed to delete URL from database")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal_server_error",
			})
		}

		find, err := urlCollection.Find(ctx, bson.D{{"user_id", claims.Subject}}, options.Find().
			SetSort(bson.D{{"created_at", -1}}).
			SetLimit(10))
		if err != nil {
			log.Error().Err(err).Msg("Failed to find URLs for user")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal_server_error",
			})
		}
		var urls []URL
		if err = find.All(ctx, &urls); err != nil {
			log.Error().Err(err).Msg("Failed to decode URLs for user")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal_server_error",
			})
		}

		return c.Render("url-list", URLListData{
			URLs: urls,
		})
	})

	app.Get("/:shortUrl\\+", func(c fiber.Ctx) error {
		var url URL
		err := urlCollection.FindOne(ctx, bson.D{{"short_url", c.Params("shortUrl")}}).Decode(&url)

		if errors.Is(err, mongo.ErrNoDocuments) {
			return c.Status(fiber.StatusNotFound).SendString("404 Not Found")
		}
		if err != nil {
			log.Error().Err(err).Msg("Failed to find URL in database")
			return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
		}

		return c.JSON(url)
	})

	app.Get("/:shortUrl", func(c fiber.Ctx) error {
		var url URL
		err := urlCollection.FindOne(ctx, bson.D{{"short_url", c.Params("shortUrl")}}).Decode(&url)

		if errors.Is(err, mongo.ErrNoDocuments) {
			return c.Status(fiber.StatusNotFound).SendString("404 Not Found")
		}
		if err != nil {
			log.Error().Err(err).Msg("Failed to find URL in database")
			return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
		}

		return c.Redirect().Status(fiber.StatusFound).To(url.OriginalURL)
	})

	_ = app.Listen(":3000")
}

func renderAuth(c fiber.Ctx, ctx context.Context, user User, settings Settings, urlCollection *mongo.Collection) error {
	now := time.Now()
	untilMaxEnabled := settings.MaxDuration != time.Duration(0)

	var notices []string

	if user.Admin {
		notices = append(notices, "You are an admin of this Pixli instance. You are exempt from the limitations.")
	}

	if untilMaxEnabled {
		// TODO: I can make this better

		var durationString string
		totalMinutes := int(settings.MaxDuration.Minutes())

		years := totalMinutes / (365 * 24 * 60)
		days := (totalMinutes % (365 * 24 * 60)) / (24 * 60)
		hours := (totalMinutes % (24 * 60)) / 60
		minutes := totalMinutes % 60

		if years > 0 {
			durationString += fmt.Sprintf("%d year", years)
			if years > 1 {
				durationString += "s"
			}
			durationString += " "
		}

		if days > 0 {
			durationString += fmt.Sprintf("%d day", days)
			if days > 1 {
				durationString += "s"
			}
			durationString += " "
		}

		if hours > 0 {
			durationString += fmt.Sprintf("%d hour", hours)
			if hours > 1 {
				durationString += "s"
			}
			durationString += " "
		}

		if minutes > 0 {
			durationString += fmt.Sprintf("%d minute", minutes)
			if minutes > 1 {
				durationString += "s"
			}
		}

		notices = append(notices, fmt.Sprintf("This Pixli instance only allows you to set a maximum duration of %s for shortened URLs.", durationString))
		notices = append(notices, "URLs shortened via ShareX will be set to the maximum duration.")
	}

	find, err := urlCollection.Find(ctx, bson.D{{"user_id", user.ID}}, options.Find().
		SetSort(bson.D{{"created_at", -1}}).
		SetLimit(10))
	if err != nil {
		log.Error().Err(err).Msg("Failed to find URLs for user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal_server_error",
		})
	}
	var urls []URL
	if err = find.All(ctx, &urls); err != nil {
		log.Error().Err(err).Msg("Failed to decode URLs for user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal_server_error",
		})
	}

	return c.Render("index", IndexData{
		Auth:            true,
		User:            user,
		UntilMin:        now.Format(time.RFC3339),
		UntilMaxEnabled: untilMaxEnabled,
		UntilMax:        now.Add(settings.MaxDuration).Format(time.RFC3339),
		Notices:         notices,
		URLs:            urls,
	})
}
