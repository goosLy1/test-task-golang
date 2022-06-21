package models

// import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	// Id       primitive.ObjectID
	Uuid     string `json:"uuid"`
	Name     string `json:"name"`
	Password string `json:"password"`
}
