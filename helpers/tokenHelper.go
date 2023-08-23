package helper

import (
	"fmt"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	constant "github.com/tontanh/preject_go/constants"
	"github.com/tontanh/preject_go/database"
	"go.mongodb.org/mongo-driver/mongo"
)

type SignedDetails struct {
	Email      string
	First_name string
	Last_name  string
	Uid        string
	User_type  string
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, constant.UserCollection)

var SECRET_KEY string = os.Getenv("SECRET_KEY")

func GenerateAllTokens(email string, firstName string, lastName string, userType string, uid string) (signedToken string, signedRefresh string, err error) {
	secretKey := []byte(SECRET_KEY)
	claims := &SignedDetails{
		Email:      email,
		First_name: firstName,
		Last_name:  lastName,
		Uid:        uid,
		User_type:  userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}
	refreshClaim := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
		},
	}
	// token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err = accessToken.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	// refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaim)
	signedRefresh, err = refreshToken.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	return signedToken, signedRefresh, err
}

func ValidateToken(signedToken string) (claims *SignedDetails, msg string) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)
	if err != nil {
		msg = err.Error()
		return
	}
	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = fmt.Sprintf("the token is invalid")
		msg = err.Error()
		return
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		msg = fmt.Sprintf("the token is expired")
		msg = err.Error()
		return
	}
	return claims, msg
}
