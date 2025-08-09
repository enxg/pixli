package main

import (
	"encoding/base64"
	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/client"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/gofiber/template/html/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-querystring/query"
	_ "github.com/joho/godotenv/autoload"
	"github.com/rs/zerolog/log"
	"os"
	"strconv"
	"time"
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

type User struct {
	ID       string
	Username string
}

var UserKey struct{}

func main() {
	ghClientId := os.Getenv("GITHUB_CLIENT_ID")
	ghClientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

	jwtSecret, err := base64.RawStdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to decode JWT secret")
	}

	cc := client.New()
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
			c.Locals(UserKey, User{
				ID:       claims.Subject,
				Username: claims.Username,
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
			return c.Render("index", fiber.Map{
				"Auth":           false,
				"GithubClientID": ghClientId,
				"Username":       "",
			})
		}

		if user, ok := c.Locals(UserKey).(User); ok {
			return c.Render("index", fiber.Map{
				"Auth":           true,
				"GithubClientID": ghClientId,
				"Username":       user.Username,
			})
		}

		authCode := c.Query("code")

		if authCode == "" {
			return c.Render("index", fiber.Map{
				"Auth":           false,
				"GithubClientID": ghClientId,
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

		claims := JWTClaims{
			Username: userResp.Username,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   strconv.FormatInt(userResp.ID, 10),
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

		return c.Render("index", fiber.Map{
			"Auth":           true,
			"GithubClientID": ghClientId,
			"Username":       userResp.Username,
		})
	})

	_ = app.Listen(":3000")
}
