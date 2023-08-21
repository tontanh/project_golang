package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	Id         primitive.ObjectID `bson:"_id"`
	First_name *string            `json:"first_name" validate:"required,min=2,max=100"`
	Last_name  *string            `json:"last_name" validate:"required,min=2,max=100"`
	Password   *string            `json:"password" validate:"required,min=6"`
	Email      *string            `json:"email" validate:"omitempty,email"`
	Phone      *string            `json:"phone" validate:"omitempty"`
	Image      *string            `json:"Image" validate:"omitempty"`
	Address    *string            `json:"address" validate:"omitempty"`
	// Token         *string            `json:"token"`
	// Refresh_token *string            `json:"refresh_token"`
	User_type *string   `json:"user_type" validate:"required,eq=ADMIN|eq=USER"`
	CreateAt  time.Time `json:"create_at"`
	UpdateAt  time.Time `json:"update_at"`
	User_id   string    `json:"user_id"`
}
