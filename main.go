package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string
	Password string
}

var db *gorm.DB

func getRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got / request\n")
	io.WriteString(w, "This is my website!\n")
}

func getHello(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got /hello request\n")
	io.WriteString(w, "Hello, HTTP test2!\n")

	// Create
	db.Create(&User{Username: "test", Password: "testpass"})
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

	http.HandleFunc("/", getRoot)
	http.HandleFunc("/hello", getHello)

	errHttp := http.ListenAndServe(":3333", nil)

	if errHttp != nil {
		panic(errHttp)
	}
}
