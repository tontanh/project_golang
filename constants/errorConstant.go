package constant

import "github.com/gin-gonic/gin"

func ErrMsg(msg string) gin.H {
   return  gin.H{"error": msg}
}