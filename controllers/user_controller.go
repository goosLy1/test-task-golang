package controllers

import (
	"context"
	"net/http"
	"os"
	"test-task-golang/configs"
	"test-task-golang/models"
	"test-task-golang/responses"
	"test-task-golang/services"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
	"github.com/twinj/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")

func CreateUser(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var user models.User
	defer cancel()

	if err := c.BodyParser(&user); err != nil {
		return err
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	newUser := models.User{
		Uuid:     uuid.NewV4().String(),
		Name:     user.Name,
		Password: string(hashPassword),
	}

	result, err := userCollection.InsertOne(ctx, newUser)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	return c.Status(http.StatusCreated).JSON(responses.UserResponse{Status: http.StatusCreated, Message: "success", Data: &fiber.Map{"data": result}})

}

func Login(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var data map[string]string

	var user models.User
	defer cancel()

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	err := userCollection.FindOne(ctx, bson.M{"uuid": data["uuid"]}).Decode(&user)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"message": "user not found"}})
	}

	// res := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(data["password"]))
	// if res != nil {
	// 	return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"message": "incorrect password"}})
	// }

	token, err := services.CreateToken(user.Uuid)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	services.HashAndSaveRefreshTokenIntoDb(userCollection, ctx, c, token, data)

	return c.Status(http.StatusCreated).JSON(responses.UserResponse{Status: http.StatusCreated, Message: "success", Data: &fiber.Map{"data": token}})
}

func Refresh(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	var data map[string]string

	defer cancel()

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	refreshToken := data["refresh_token"]

	token, err := jwt.Parse(refreshToken, func(t *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})

	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": "Refresh token expired"}})
	}

	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return c.Status(http.StatusUnauthorized).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": "Invalid refresh token"}})
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userUUID, ok := claims["uuid"].(string)
		if !ok {
			return c.Status(http.StatusUnprocessableEntity).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": "Error occurred"}})
		}
		ts, createErr := services.CreateToken(userUUID)
		if createErr != nil {
			return c.Status(http.StatusForbidden).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": createErr.Error()}})
		}

		services.HashAndSaveRefreshTokenIntoDb(userCollection, ctx, c, ts, data)
		return c.Status(http.StatusCreated).JSON(responses.UserResponse{Status: http.StatusCreated, Message: "success", Data: &fiber.Map{"data": ts}})
	} else {
		return c.Status(http.StatusUnauthorized).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": "Refresh token error"}})
	}

}
