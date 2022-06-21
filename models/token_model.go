package models

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AtExpires    int64
	RtExpires    int64
}
