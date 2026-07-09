package iitkgp_erp_login

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/go-ping/ping"
	"golang.org/x/term"
)

const logging = true

const ssoTokenPrefix = "ssoToken="

var ssoTokenRegex = regexp.MustCompile(`ssoToken=[^"'\s&]+`)

type loginDetails struct {
	userID       string
	password     string
	answer       string
	requestedURL string
	emailOTP     string
}

type erpCreds struct {
	RollNumber               string            `json:"roll_number"`
	Password                 string            `json:"password"`
	SecurityQuestionsAnswers map[string]string `json:"answers"`
}

func inputCreds(client *http.Client, logging bool) (loginDetails, error) {
	loginParams := loginDetails{
		requestedURL: HOMEPAGE_URL,
	}

	if fileExists("erpcreds.json") {
		log.Println("Found ERP Credentials file")

		credsByte, err := os.ReadFile("erpcreds.json")
		if err != nil {
			return loginDetails{}, fmt.Errorf("reading erpcreds.json: %w", err)
		}

		var creds erpCreds
		if err := json.Unmarshal(credsByte, &creds); err != nil {
			return loginDetails{}, fmt.Errorf("parsing erpcreds.json: %w", err)
		}

		question, err := getSecretQuestion(client, creds.RollNumber, logging)
		if err != nil {
			return loginDetails{}, err
		}

		answer, ok := creds.SecurityQuestionsAnswers[question]
		if !ok {
			return loginDetails{}, fmt.Errorf("no stored answer for security question %q", question)
		}

		loginParams.userID = creds.RollNumber
		loginParams.password = creds.Password
		loginParams.answer = answer
	} else {
		fmt.Print("Enter Roll No.: ")
		if _, err := fmt.Scan(&loginParams.userID); err != nil {
			return loginDetails{}, fmt.Errorf("reading roll number: %w", err)
		}

		fmt.Print("Enter ERP Password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return loginDetails{}, fmt.Errorf("reading password: %w", err)
		}
		loginParams.password = string(bytePassword)
		fmt.Println()

		question, err := getSecretQuestion(client, loginParams.userID, logging)
		if err != nil {
			return loginDetails{}, err
		}
		fmt.Printf("Your secret question: %s\n", question)
		fmt.Print("Enter answer to your secret question: ")
		byteAnswer, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return loginDetails{}, fmt.Errorf("reading answer: %w", err)
		}
		loginParams.answer = string(byteAnswer)
		fmt.Println()
	}
	return loginParams, nil
}

func getSecretQuestion(client *http.Client, rollNumber string, logging bool) (string, error) {
	data := map[string][]string{
		"user_id": {rollNumber},
	}

	res, err := client.PostForm(SECRET_QUESTION_URL, data)
	if err != nil {
		return "", fmt.Errorf("fetching security question: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("reading security question: %w", err)
	}

	if logging {
		log.Println("Fetched Security Question")
	}

	return strings.TrimSpace(string(body)), nil
}

// isOTPRequired pings the ERP network to decide whether an OTP is needed. If the
// ping cannot be performed it fails safe by assuming an OTP is required.
func isOTPRequired() (bool, error) {
	pinger, err := ping.NewPinger(PING_URL)
	if err != nil {
		return false, fmt.Errorf("creating pinger: %w", err)
	}
	pinger.Count = 1
	pinger.Timeout = 4 * time.Second

	if err := pinger.Run(); err != nil {
		return true, nil
	}

	return pinger.Statistics().PacketsRecv != 1, nil
}

func isSessionAlive(client *http.Client, logging bool) (bool, string, error) {
	if !fileExists(".session") {
		return false, "", nil
	}

	if logging {
		log.Println("Found session file")
		log.Println("Checking session validity...")
	}

	sessionByte, err := os.ReadFile(".session")
	if err != nil {
		return false, "", fmt.Errorf("reading .session: %w", err)
	}
	ssoToken := strings.TrimSpace(string(sessionByte))
	if ssoToken == "" {
		return false, "", nil
	}

	res, err := client.Get(HOMEPAGE_URL + "?" + ssoToken)
	if err != nil {
		return false, "", fmt.Errorf("checking session: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return false, "", fmt.Errorf("reading session check response: %w", err)
	}

	// The logged-out homepage is exactly 4145 bytes. Comparing the decoded body
	// length works even when the response is chunked (ContentLength == -1).
	bodyLen := len(body)
	log.Printf("Response body length: %d bytes\n", bodyLen)
	valid := len(body) < 5000

	if logging {
		if valid {
			log.Println("Session valid")
		} else {
			log.Println("Session invalid")
		}
	}

	return valid, ssoToken, nil
}

// extractSSOToken pulls the "ssoToken=..." value out of the login response HTML.
func extractSSOToken(body string) (string, error) {
	token := ssoTokenRegex.FindString(body)
	if token == "" {
		return "", errors.New("login failed: ssoToken not found in response (check credentials/OTP)")
	}
	return token, nil
}

// ERPSession logs in to the IIT Kharagpur ERP (reusing a cached session when
// possible) and returns an authenticated HTTP client together with the ssoToken.
func ERPSession() (*http.Client, string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating cookie jar: %w", err)
	}
	client := &http.Client{Jar: jar}

	isSession, ssoToken, err := isSessionAlive(client, logging)
	if err != nil {
		return nil, "", err
	}

	if !isSession {
		loginParams, err := inputCreds(client, logging)
		if err != nil {
			return nil, "", err
		}

		otpRequired, err := isOTPRequired()
		if err != nil {
			return nil, "", err
		}
		if otpRequired {
			if logging {
				log.Println("OTP is required")
			}
			loginParams.emailOTP, err = fetchOTP(client, loginParams, logging)
			if err != nil {
				return nil, "", err
			}
		}

		data := url.Values{}
		data.Set("user_id", loginParams.userID)
		data.Set("password", loginParams.password)
		data.Set("answer", loginParams.answer)
		data.Set("requestedUrl", loginParams.requestedURL)
		data.Set("email_otp", loginParams.emailOTP)

		res, err := client.PostForm(LOGIN_URL, data)
		if err != nil {
			return nil, "", fmt.Errorf("posting login: %w", err)
		}
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, "", fmt.Errorf("reading login response: %w", err)
		}

		ssoToken, err = extractSSOToken(string(body))
		if err != nil {
			return nil, "", err
		}

		log.Println("ERP login complete!")

		if err := os.WriteFile(".session", []byte(ssoToken), 0600); err != nil {
			return nil, "", fmt.Errorf("writing .session: %w", err)
		}
	}

	u, err := url.Parse("https://erp.iitkgp.ac.in/")
	if err != nil {
		return nil, "", fmt.Errorf("parsing ERP URL: %w", err)
	}

	cookieValue := strings.TrimPrefix(ssoToken, ssoTokenPrefix)
	client.Jar.SetCookies(u, []*http.Cookie{{Name: "ssoToken", Value: cookieValue}})

	return client, ssoToken, nil
}
