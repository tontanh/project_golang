package routes

import (
	"github.com/gin-gonic/gin"
	controller "github.com/tontanh/preject_go/controllers"
	"github.com/tontanh/preject_go/middleware"
)

func AdminRoutes(incomingRoutes *gin.Engine) {
	// use Authenticate all route
	// incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("get_my_user", controller.GetUsersPublic())
	//  use Authenticate some route
	incomingRoutes.GET("users", middleware.Authenticate(), controller.GetUsers())
	incomingRoutes.GET("users/:user_id", middleware.Authenticate(), controller.GetUser())
}
