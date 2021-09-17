package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-resty/resty/v2"

	"bookstore_oauth-go/oauth/errors"
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	client = resty.New()

	// oauthRestClient = rest.RequestBuilder{
	// 	BaseURL: "http://localhost:8080",
	// 	Timeout: 200 * time.Millisecond,
	// }
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {

	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 10)
	if err != nil {
		return 0
	}
	return clientId

}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 10)
	if err != nil {
		return 0
	}
	return callerId
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}
	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		return err
	}
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *errors.RestErr) {

	response, _ := client.R().Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	// response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	if response == nil || response.Body() == nil {
		return nil, errors.NewInternalServerError("invalid response when trying to get access_token")
	}
	if response.StatusCode() > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(response.Body(), &restErr)
		if err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to get access_token")

		}
		return nil, &restErr
	}
	var at accessToken
	if err := json.Unmarshal(response.Body(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshal access_token response")
	}
	return &at, nil
}
