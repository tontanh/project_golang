package routes

import (
	"github.com/gin-gonic/gin"
	controller "github.com/tontanh/preject_go/controllers"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("users/signup", controller.SignUp())
	incomingRoutes.POST("users/login", controller.Login())
	incomingRoutes.POST("users/get_access_token",controller.GetAccessToken())
}
