package routes

import (
	controller "authentication/controllers"

	"github.com/gin-gonic/gin"
)

func TokenRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/get_tokens", controller.GetTokens())
	incomingRoutes.POST("/refresh_tokens", controller.RefreshTokens())
}
