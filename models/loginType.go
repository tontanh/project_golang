package models

type LoginInput struct {
	Uuid          string `json:"uuid"`
	Email         string `json:"email" validate:"omitempty,email"`
	Phone         string `json:"phone" validate:"omitempty"`
	Password      string `json:"password" validate:"required,min=6"`
	User_agent    string `json:"user_agent"`
	Device_token  string `json:"device_token"`
	Ip_address    string `json:"ip_address"`
	Refresh_token string `json:"refresh_token"`
}
