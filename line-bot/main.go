package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/line/line-bot-sdk-go/v7/linebot"
)

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	secret := os.Getenv("CHANNEL_SECRET")
	if !verifySignature(secret, request.Headers["X-Line-Signature"], []byte(request.Body)) {
		return events.APIGatewayProxyResponse{}, errors.New("invalid: wrong signature")
	}

	content := &struct {
		Events []*linebot.Event `json:"events"`
	}{}
	if err := json.Unmarshal([]byte(request.Body), content); err != nil {
		return events.APIGatewayProxyResponse{}, err
	}

	bot, err := linebot.New(
		secret,
		os.Getenv("CHANNEL_ACCESS_TOKEN"),
	)
	if err != nil {
		return events.APIGatewayProxyResponse{}, errors.New("failed: can't create bot")
	}

	for _, event := range content.Events {
		if event.Type == linebot.EventTypeMessage {
			replyToken := event.ReplyToken
			switch message := event.Message.(type) {
			case *linebot.TextMessage:
				if _, err := bot.ReplyMessage(replyToken, linebot.NewTextMessage(message.Text)).Do(); err != nil {
					return events.APIGatewayProxyResponse{}, errors.New("failed: can't reply message")
				}
			default:
				if _, err := bot.ReplyMessage(replyToken, linebot.NewTextMessage("おうむ返しに対応していないメッセージです")).Do(); err != nil {
					return events.APIGatewayProxyResponse{}, errors.New("failed: can't reply message")
				}
			}
		}
	}
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
	}, nil
}

func verifySignature(channelSecret, signature string, body []byte) bool {
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	hash := hmac.New(sha256.New, []byte(channelSecret))

	_, err = hash.Write(body)
	if err != nil {
		return false
	}

	return hmac.Equal(decoded, hash.Sum(nil))
}

func main() {
	lambda.Start(handler)
}
