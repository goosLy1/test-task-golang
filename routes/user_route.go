package routes

import (
	"github.com/gofiber/fiber/v2"

	"test-task-golang/controllers"
)

func UserRoute(app *fiber.App) {
	app.Post("/user", controllers.CreateUser)
	app.Post("/login", controllers.Login)
	app.Post("/refresh", controllers.Refresh)
}
