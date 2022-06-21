package main

import (
	"github.com/gofiber/fiber/v2"

	"test-task-golang/configs"
	"test-task-golang/routes"
)

func main() {
	app := fiber.New()

	configs.ConnectDB()

	routes.UserRoute(app)

	app.Listen(":3000")
}
