package services

import (
	"context"
	"net/http"
	"os"
	"test-task-golang/models"
	"test-task-golang/responses"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func CreateToken(uuid string) (*models.TokenDetails, error) {
	td := &models.TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()

	var err error

	atClaims := jwt.MapClaims{
		// "id":   user.Id,
		"uuid": uuid,
		"exp":  td.AtExpires,
	}

	at := jwt.NewWithClaims(jwt.SigningMethodHS512, atClaims)

	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}

	rtClaims := jwt.MapClaims{
		"uuid": uuid,
		"exp":  td.RtExpires,
	}

	rt := jwt.NewWithClaims(jwt.SigningMethodHS512, rtClaims)

	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}

	return td, nil
}

func HashAndSaveRefreshTokenIntoDb(userCollection *mongo.Collection, ctx context.Context, c *fiber.Ctx, token *models.TokenDetails, data map[string]string) error {
	hashRefreshToken, err := bcrypt.GenerateFromPassword([]byte(token.RefreshToken), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = userCollection.UpdateOne(ctx, bson.M{"uuid": data["uuid"]}, bson.M{"$set": bson.M{"refresh_token": hashRefreshToken}})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}
	return nil
}
