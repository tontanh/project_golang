package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	constant "github.com/tontanh/preject_go/constants"
	"github.com/tontanh/preject_go/database"
	helper "github.com/tontanh/preject_go/helpers"
	"github.com/tontanh/preject_go/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, constant.UserCollection)
var tokenCollection *mongo.Collection = database.OpenCollection(database.Client, constant.TokenCollection)
var validate = validator.New()

//	func HashPassword(password string) string {
//		bcrypt.GenerateFromPassword([]byte(password), 14)
//		if err != nil {
//			log.Panic(err)
//		}
//		return string(byte)
//	}
func HashPassword(password string) string {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Panic(err)
	}
	return string(hashedPassword)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""
	if err != nil {
		msg = fmt.Sprintf("email or password is incorrect")
		check = false
	}
	return check, msg
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
		}
		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the email"})

		}
		password := HashPassword(*user.Password)
		user.Password = &password

		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the phone"})

		}
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "this email or phone already exist"})
		}
		user.CreateAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.UpdateAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Id = primitive.NewObjectID()
		user.User_id = user.Id.Hex()
		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, *&user.User_id)
		// user.Token = &token
		// user.Refresh_token = &refreshToken
		InsertAllTokens(token, refreshToken, user.User_id)
		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		defer cancel()
		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": " email or password is incorrect"})
			return
		}
		passwordValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
		if passwordValid != true {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		}
		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, *&foundUser.User_id)
		UpdateAllTokens(token, refreshToken, foundUser.User_id)
		userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, foundUser)

	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")
		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		c.JSON(http.StatusOK, user)
	}
}

func UpdateAllTokens(signedToken string, signedRefreshToken string, userId string) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	var updateObj primitive.D

	updateObj = append(updateObj, bson.E{Key: "token", Value: signedToken})
	// updateObj = append(updateObj, bson.E{"token", signedToken})
	updateObj = append(updateObj, bson.E{Key: "refresh_token", Value: signedRefreshToken})
	// updateObj = append(updateObj, bson.E{"refresh_token", signedRefreshToken})

	Updated_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{Key: "updated_at", Value: Updated_at})
	// updateObj = append(updateObj, bson.E{"updated_at", Updated_at})
	upsert := true

	filter := bson.M{"user_id": userId}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}
	_, err := userCollection.UpdateOne(
		ctx, filter, bson.D{
			{Key: "$set", Value: updateObj},
			// {"$set", updateObj},
		}, &opt,
	)
	defer cancel()
	if err != nil {
		log.Panic(err)
		return
	}
	return
}
func InsertAllTokens(signedToken string, signedRefreshToken string, userId string) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	var authentication models.Authentication
	authentication.Id = primitive.NewObjectID()
	authentication.User_id = userId
	authentication.Token = &signedToken
	authentication.Refresh_token = &signedRefreshToken
	authentication.CreateAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	authentication.UpdateAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	resultInsertionNumber, insertErr := tokenCollection.InsertOne(ctx, authentication)
	defer cancel()
	if insertErr != nil {
		log.Panic(insertErr)
		return
	}
	fmt.Println(resultInsertionNumber)
	return
}
func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := helper.CheckUserType(c, "ADMIN") // Missing assignment operator ":="
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		recordPerPage, err := strconv.Atoi(c.DefaultQuery("recordPerPage", "10"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}

		page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
		if err != nil || page < 1 {
			page = 1
		}
		startIndex := (page - 1) * recordPerPage

		matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}
		// matchStage := bson.D{{"$match", bson.D{{}}}}
		groupStage := bson.D{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
				{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
				{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
			}},
			// {"$group", bson.D{
			// 	{"_id", bson.D{{"_id", "null"}}},
			// 	{"total_count", bson.D{{"$sum", 1}}},
			// 	{"data", bson.D{{"$push", "$$ROOT"}}},
			// }},
		}
		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}},
			}},
			// {"$project", bson.D{
			// 	{"_id", 0},
			// 	{"total_count", 1},
			// 	{"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage}}}},
			// }},
		}

		pipeline := mongo.Pipeline{matchStage, groupStage, projectStage}

		cursor, err := userCollection.Aggregate(ctx, pipeline)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error while aggregating user items"})
			return
		}
		defer cursor.Close(ctx)

		var result []bson.M
		if err := cursor.All(ctx, &result); err != nil {
			log.Fatal(err)
		}

		if len(result) > 0 {
			c.JSON(http.StatusOK, result[0])
		} else {
			c.JSON(http.StatusOK, bson.M{"total_count": 0, "user_items": []bson.M{}})
		}
	}
}

func GetUsersPublic() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, bson.M{"message": "get public"})
	}
}
