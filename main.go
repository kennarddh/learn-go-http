package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"encoding/json"

	"example.com/main/hash"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string
	Password string
}

type UserReqBody struct {
	Username string
	Password string
}

var db *gorm.DB

var argon2Params = &hash.Argon2Params{
	Memory:      16 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  64,
	KeyLength:   64,
}

func register(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got /register request\n")

	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		io.WriteString(w, "{\"success\": false, \"message\": \"Only Post Method Is Allowed\"}")

		return
	}

	if r.Body != nil {
		defer r.Body.Close()
	}

	body, readErr := io.ReadAll(r.Body)

	if readErr != nil {
		fmt.Println("Read Body Error")
		fmt.Println(readErr)

		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "{\"success\": false, \"message\": \"Internal Server Error\"}")

		return
	}

	userReqBody := UserReqBody{}

	jsonErr := json.Unmarshal(body, &userReqBody)

	if jsonErr != nil {
		fmt.Println("JSON Parse Error")
		fmt.Println(jsonErr)

		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "{\"success\": false, \"message\": \"Invalid Body\"}")

		return
	}

	if userReqBody.Username == "" {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "{\"success\": false, \"message\": \"Username Cannot Be Empty\"}")

		return
	}

	if userReqBody.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "{\"success\": false, \"message\": \"Password Cannot Be Empty\"}")

		return
	}

	hashedPassword, hashErr := hash.HashArgon2(userReqBody.Password, argon2Params)

	if hashErr != nil {
		fmt.Println("Hashing Error")
		fmt.Println(hashErr)

		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "{\"success\": false, \"message\": \"Internal Server Error\"}")

		return
	}

	// Create
	db.Create(&User{
		Username: userReqBody.Username,
		Password: string(hashedPassword),
	})

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "{\"success\": true, \"message\": \"Success Register\"}")
}

func login(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got /login request\n")

	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		io.WriteString(w, "{\"success\": false, \"message\": \"Only Post Method Is Allowed\"}")

		return
	}

	if r.Body != nil {
		defer r.Body.Close()
	}

	body, readErr := io.ReadAll(r.Body)

	if readErr != nil {
		fmt.Println("Read Body Error")
		fmt.Println(readErr)

		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "{\"success\": false, \"message\": \"Internal Server Error\"}")

		return
	}

	userReqBody := UserReqBody{}

	jsonErr := json.Unmarshal(body, &userReqBody)

	if jsonErr != nil {
		fmt.Println("JSON Parse Error")
		fmt.Println(jsonErr)

		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "{\"success\": false, \"message\": \"Invalid Body\"}")

		return
	}

	if userReqBody.Username == "" {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "{\"success\": false, \"message\": \"Username Cannot Be Empty\"}")

		return
	}

	if userReqBody.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "{\"success\": false, \"message\": \"Password Cannot Be Empty\"}")

		return
	}

	var user User
	dbErr := db.First(&user, "Username = ?", userReqBody.Username).Error

	if errors.Is(dbErr, gorm.ErrRecordNotFound) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "{\"success\": false, \"message\": \"Can't Find User\"}")

		return
	}

	match, verifyErr := hash.VerifyArgon2(userReqBody.Password, user.Password)

	if verifyErr != nil {
		fmt.Println("Verify Error")
		fmt.Println(verifyErr)

		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "{\"success\": false, \"message\": \"Internal Server Error\"}")

		return
	}

	if !match {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "{\"success\": false, \"message\": \"Wrong password\"}")

		return
	}

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "{\"success\": true, \"message\": \"Success Login\"}")
}

func main() {
	DATABASE_URL := os.Getenv("DATABASE_URL")

	newDB, err := gorm.Open(mysql.Open(DATABASE_URL), &gorm.Config{})

	db = newDB

	if err != nil {
		panic(err)
	}

	// Migrate the schema
	db.AutoMigrate(&User{})

	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)

	errHttp := http.ListenAndServe(":3333", nil)

	if errHttp != nil {
		panic(errHttp)
	}
}
