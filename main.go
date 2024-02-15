package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"encoding/json"

	"example.com/main/hash"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
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

type UserClaims struct {
	Id uint `json:"id"`
	jwt.MapClaims
}

var jwtKey []byte

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
	dbErr := db.Where(&User{Username: userReqBody.Username}).First(&user).Error

	if errors.Is(dbErr, gorm.ErrRecordNotFound) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "{\"success\": false, \"message\": \"Can't Find User\"}")

		return
	} else if dbErr != nil {
		fmt.Println("Gorm Error")
		fmt.Println(dbErr)

		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "{\"success\": false, \"message\": \"Internal Server Error\"}")

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

	userClaims := UserClaims{
		Id: user.ID,
		MapClaims: jwt.MapClaims{
			"exp": time.Now().Add(time.Minute).UnixMilli() / 1000, // In Seconds
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaims)

	tokenString, jwtSigNErr := token.SignedString(jwtKey)

	if jwtSigNErr != nil {
		fmt.Println("JWT Sign Error")
		fmt.Println(jwtSigNErr)

		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "{\"success\": false, \"message\": \"Internal Server Error\"}")

		return
	}

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, fmt.Sprintf("{\"success\": true, \"message\": \"Success Login\", \"token\": \"%s\"}", tokenString))
}

func verifyJWT(endpointHandler func(http.ResponseWriter, *http.Request, uint)) http.HandlerFunc {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		tokenArr := request.Header["Token"]

		if tokenArr == nil {
			writer.WriteHeader(http.StatusUnauthorized)
			io.WriteString(writer, "{\"success\": false, \"message\": \"No token provided\"}")

			return
		}

		if len(tokenArr) > 1 {
			writer.WriteHeader(http.StatusUnauthorized)
			io.WriteString(writer, "{\"success\": false, \"message\": \"More than 1 token provided\"}")

			return
		}

		tokenStr := tokenArr[0]

		parsedToken, parseJWTError := jwt.ParseWithClaims(
			tokenStr,
			&UserClaims{},
			func(token *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			},
		)

		if parseJWTError != nil {
			if errors.Is(parseJWTError, jwt.ErrTokenExpired) {
				writer.WriteHeader(http.StatusUnauthorized)
				io.WriteString(writer, "{\"success\": false, \"message\": \"Expired Token\"}")
			} else if errors.Is(parseJWTError, jwt.ErrTokenMalformed) {
				writer.WriteHeader(http.StatusUnauthorized)
				io.WriteString(writer, "{\"success\": false, \"message\": \"Invalid Token\"}")
			} else if errors.Is(parseJWTError, jwt.ErrSignatureInvalid) {
				writer.WriteHeader(http.StatusUnauthorized)
				io.WriteString(writer, "{\"success\": false, \"message\": \"Invalid Token\"}")
			} else {
				fmt.Println("JWT Parse Error")
				fmt.Println(parseJWTError)

				writer.WriteHeader(http.StatusInternalServerError)
				io.WriteString(writer, "{\"success\": false, \"message\": \"Internal Server Error\"}")
			}

			return
		}

		if !parsedToken.Valid {
			writer.WriteHeader(http.StatusUnauthorized)
			io.WriteString(writer, "{\"success\": false, \"message\": \"Invalid token\"}")

			return
		}

		userClaim, ok := parsedToken.Claims.(*UserClaims)

		if !ok {
			fmt.Println("JWT Claims Error")

			writer.WriteHeader(http.StatusInternalServerError)
			io.WriteString(writer, "{\"success\": false, \"message\": \"Internal Server Error\"}")

			return
		}

		userID := userClaim.Id

		endpointHandler(writer, request, userID)
	})
}

func user(w http.ResponseWriter, r *http.Request, userID uint) {
	fmt.Printf("got /user request\n")

	w.Header().Set("Content-Type", "application/json")

	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		io.WriteString(w, "{\"success\": false, \"message\": \"Only Get Method Is Allowed\"}")

		return
	}

	var user User
	dbErr := db.First(&user, userID).Error

	if errors.Is(dbErr, gorm.ErrRecordNotFound) {
		fmt.Println("Gorm Error. Can't find user from token")
		fmt.Println(dbErr)

		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "{\"success\": false, \"message\": \"Internal Server Error\"}")

		return
	} else if dbErr != nil {
		fmt.Println("Gorm Error")
		fmt.Println(dbErr)

		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "{\"success\": false, \"message\": \"Internal Server Error\"}")

		return
	}

	w.WriteHeader(http.StatusOK)
	io.WriteString(
		w,
		fmt.Sprintf(
			"{\"success\": true, \"message\": \"Success Get Data\", \"data\": {\"username\":\"%s\",\"createdAt\":%d}}",
			user.Username,
			user.CreatedAt.UnixMilli(),
		),
	)
}

func main() {
	executable, executableErr := os.Executable()

	if executableErr != nil {
		log.Fatal("Error finding executable", executableErr)
	}

	executableDirectory := filepath.Dir(executable)

	envPath := filepath.Join(executableDirectory, "./.env")

	dotEnvErr := godotenv.Load(envPath)

	if dotEnvErr != nil {
		log.Fatal("Error loading .env file", dotEnvErr)
	}

	jwtKey = []byte(os.Getenv("JWT_KEY"))

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
	http.HandleFunc("/user", verifyJWT(user))

	errHttp := http.ListenAndServe(":3333", nil)

	if errHttp != nil {
		panic(errHttp)
	}
}
