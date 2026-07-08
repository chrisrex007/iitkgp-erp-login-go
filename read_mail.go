package iitkgp_erp_login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gmail "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

const (
	redirectURL = "http://localhost:7007"
	otpQuery    = "from:erpkgp@adm.iitkgp.ac.in is:unread subject: otp"
)

var otpDigits = regexp.MustCompile(`[0-9]+`)

type otpResponse struct {
	Message string `json:"msg"`
}

// requestOTP asks ERP to email a one-time password to the registered address.
func requestOTP(client *http.Client, loginParams loginDetails, logging bool) error {
	data := url.Values{}
	data.Set("typeee", "SI")
	data.Set("user_id", loginParams.userID)
	data.Set("password", loginParams.password)
	data.Set("answer", loginParams.answer)

	res, err := client.PostForm(OTP_URL, data)
	if err != nil {
		return fmt.Errorf("requesting OTP: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading OTP response: %w", err)
	}

	var otpRes otpResponse
	if err := json.Unmarshal(body, &otpRes); err != nil {
		return fmt.Errorf("parsing OTP response %q: %w", string(body), err)
	}

	// ERP does not return a status code we can rely on, so treat the response
	// as a failure only when it is empty or explicitly signals an error rather
	// than matching its exact success sentence (which changes over time).
	msg := strings.ToLower(otpRes.Message)
	if strings.TrimSpace(msg) == "" || strings.Contains(msg, "error") ||
		strings.Contains(msg, "invalid") || strings.Contains(msg, "incorrect") {
		return fmt.Errorf("failed to request OTP: %s", strings.TrimSpace(otpRes.Message))
	}

	if logging {
		log.Println("Requested OTP")
	}
	return nil
}

func getMsgID(service *gmail.Service) (string, error) {
	results, err := service.Users.Messages.List("me").Q(otpQuery).MaxResults(1).Do()
	if err != nil {
		return "", fmt.Errorf("listing OTP messages: %w", err)
	}
	if len(results.Messages) != 0 {
		return results.Messages[0].Id, nil
	}
	return "", nil
}

func fetchOTP(client *http.Client, loginParams loginDetails, logging bool) (string, error) {
	if fileExists("client_secret.json") || fileExists(".token") {
		return fetchOTPFromMail(client, loginParams, logging)
	}
	return fetchOTPFromInput(client, loginParams)
}

// extractMessageBody walks a Gmail message payload, descending into multipart
// parts, and returns the first decoded text body it finds.
func extractMessageBody(part *gmail.MessagePart) (string, error) {
	if part == nil {
		return "", nil
	}
	if part.Body != nil && part.Body.Data != "" {
		decoded, err := base64.URLEncoding.DecodeString(part.Body.Data)
		if err != nil {
			return "", fmt.Errorf("decoding message body: %w", err)
		}
		return string(decoded), nil
	}
	for _, p := range part.Parts {
		body, err := extractMessageBody(p)
		if err != nil {
			return "", err
		}
		if body != "" {
			return body, nil
		}
	}
	return "", nil
}

func fetchOTPFromMail(client *http.Client, loginParams loginDetails, logging bool) (string, error) {
	ctx := context.Background()

	conf := oauth2.Config{
		Scopes:      []string{gmail.GmailReadonlyScope},
		Endpoint:    google.Endpoint,
		RedirectURL: redirectURL,
	}

	secretByte, err := os.ReadFile("client_secret.json")
	if err != nil {
		return "", fmt.Errorf("reading client_secret.json: %w", err)
	}

	var secret map[string]map[string]json.RawMessage
	if err := json.Unmarshal(secretByte, &secret); err != nil {
		return "", fmt.Errorf("parsing client_secret.json: %w", err)
	}
	if err := json.Unmarshal(secret["installed"]["client_id"], &conf.ClientID); err != nil {
		return "", fmt.Errorf("parsing client_id: %w", err)
	}
	if err := json.Unmarshal(secret["installed"]["client_secret"], &conf.ClientSecret); err != nil {
		return "", fmt.Errorf("parsing client_secret: %w", err)
	}

	var token *oauth2.Token
	if fileExists(".token") {
		if logging {
			log.Println("Found token file")
		}
		tokenByte, err := os.ReadFile(".token")
		if err != nil {
			return "", fmt.Errorf("reading .token: %w", err)
		}
		if err := json.Unmarshal(tokenByte, &token); err != nil {
			return "", fmt.Errorf("parsing .token: %w", err)
		}
	} else {
		token, err = generateToken(ctx, &conf)
		if err != nil {
			return "", err
		}
		tokenJSON, err := json.Marshal(token)
		if err != nil {
			return "", fmt.Errorf("serializing token: %w", err)
		}
		if err := os.WriteFile(".token", tokenJSON, 0600); err != nil {
			return "", fmt.Errorf("writing .token: %w", err)
		}
	}

	service, err := gmail.NewService(ctx, option.WithTokenSource(conf.TokenSource(ctx, token)))
	if err != nil {
		return "", fmt.Errorf("creating gmail service: %w", err)
	}

	latestID, err := getMsgID(service)
	if err != nil {
		return "", err
	}
	if err := requestOTP(client, loginParams, logging); err != nil {
		return "", err
	}

	var mailID string
	for {
		if logging {
			log.Println("Waiting for OTP...")
		}
		mailID, err = getMsgID(service)
		if err != nil {
			return "", err
		}
		if mailID != "" && mailID != latestID {
			if logging {
				log.Println("OTP fetched")
			}
			break
		}
		time.Sleep(1 * time.Second)
	}

	message, err := service.Users.Messages.Get("me", mailID).Do()
	if err != nil {
		return "", fmt.Errorf("fetching OTP message: %w", err)
	}

	body, err := extractMessageBody(message.Payload)
	if err != nil {
		return "", err
	}

	otp := otpDigits.FindString(body)
	if otp == "" {
		return "", errors.New("no OTP digits found in message body")
	}
	return otp, nil
}

func fetchOTPFromInput(client *http.Client, loginParams loginDetails) (string, error) {
	if err := requestOTP(client, loginParams, true); err != nil {
		return "", err
	}
	var otp string
	fmt.Print("Enter OTP: ")
	if _, err := fmt.Scan(&otp); err != nil {
		return "", fmt.Errorf("reading OTP input: %w", err)
	}
	return otp, nil
}
