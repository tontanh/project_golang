package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Authentication struct {
	Id            primitive.ObjectID `bson:"_id"`
	Uuid          *string            `json:"uuid"`
	User_agent    *string            `json:"user_agent"`
	Token         *string            `json:"token"`
	Refresh_token *string            `json:"refresh_token"`
	Device_token  *string            `json:"device_token"`
	Str1          *string            `json:"str1"`
	Str2          *string            `json:"str2"`
	CreateAt      time.Time          `json:"create_at"`
	UpdateAt      time.Time          `json:"update_at"`
	User_id       string             `json:"user_id"`
}
