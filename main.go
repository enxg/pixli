package main

import (
	"encoding/base64"
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
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

type JWTClaims struct {
	Username string `json:"username"`
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
}

type Settings struct {
	MaxDuration time.Duration
	Admins      map[string]struct{}
}

type User struct {
	ID       string
	Username string
	Admin    bool
}

var UserKey struct{}

func main() {
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
			return renderAuth(c, user, settings)
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

		return renderAuth(c, user, settings)
	})

	app.Post("/shorten", func(ctx fiber.Ctx) error {

		return nil
	})

	_ = app.Listen(":3000")
}

func renderAuth(c fiber.Ctx, user User, settings Settings) error {
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
	}

	return c.Render("index", IndexData{
		Auth:            true,
		User:            user,
		UntilMin:        now.Format(time.RFC3339),
		UntilMaxEnabled: untilMaxEnabled,
		UntilMax:        now.Add(settings.MaxDuration).Format(time.RFC3339),
		Notices:         notices,
	})
}
