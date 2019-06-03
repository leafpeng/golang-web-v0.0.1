package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"

	uuid "github.com/satori/go.uuid"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"

	_ "github.com/go-sql-driver/mysql"
)

// UserInfo userinfo save inmemory
type UserInfo struct {
	UserName string
	Email    string
}

// inMemorySessions map[cookie uuid]UserInfo
var inMemorySessions = make(map[string]UserInfo)

var (
	// conn                  *sql.DB
	tpl *template.Template
	// inMemorySessions      Sessions
	createTableStatements = []string{
		`CREATE DATABASE IF NOT EXISTS leaf`,
		`USE leaf;`,
		`CREATE TABLE IF NOT EXISTS userinfo (
		id INT UNSIGNED NOT NULL AUTO_INCREMENT,
		useremail VARCHAR(64) NOT NULL,
		username VARCHAR(64) NOT NULL,
		password VARCHAR(64) NOT NULL,
		PRIMARY KEY (id))`,
	}
)

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	db := dbConn()
	err := createTable(db)
	if err != nil {
		panic(err)
	}
	defer db.Close()
}

func main() {

	r := mux.NewRouter()
	r.Handle("/favicon.ico", http.NotFoundHandler())
	r.HandleFunc("/", index).Methods("GET")
	r.HandleFunc("/login", loginGet).Methods("GET")
	r.HandleFunc("/login", loginPost).Methods("POST")
	r.HandleFunc("/logout", logout).Methods("GET")
	r.HandleFunc("/register", registerGet).Methods("GET")
	r.HandleFunc("/register", registerPost).Methods("POST")
	// r.HandleFunc("/leaf.jpg", jpg).Methods("GET")
	// r.HandleFunc("/styles.css", css).Methods("GET")
	r.PathPrefix("/styles/").Handler(http.StripPrefix("/styles/", http.FileServer(http.Dir("./styles"))))
	// r.PathPrefix("/styles.css").Handler(http.StripPrefix("/styles", http.FileServer(http.Dir("./styles"))))
	log.Println("Server starting at port 8080.")
	http.ListenAndServe(":8080", r)
}

func dbConn() *sql.DB {
	conn, err := sql.Open("mysql", "root:leaf@tcp(127.0.0.1:3306)/")
	if err != nil {
		log.Fatal("can not open db", err)
	}
	if err := conn.Ping(); err != nil {
		conn.Close()
		log.Fatal("can not establish connection", err)
	}

	log.Println("db connected!")
	return conn
}

func dbUse(db *sql.DB) {
	_, err := db.Exec("USE leaf")
	if err != nil {
		log.Fatal("can not use database leaf")
	}
}

// createTable creates the table, and if necessary, the database.
func createTable(conn *sql.DB) error {
	for _, stmt := range createTableStatements {
		_, err := conn.Exec(stmt)
		if err != nil {
			return err
		}
	}
	log.Println("table created.")
	return nil
}

func setCookieAndCreateSession(w http.ResponseWriter, un, email string) {
	sID, err := uuid.NewV4()
	if err != nil {
		log.Fatal(err)
	}
	cookie := &http.Cookie{
		Name:  "session",
		Value: sID.String(),
	}
	http.SetCookie(w, cookie)
	inMemorySessions[cookie.Value] = UserInfo{
		UserName: un,
		Email:    email,
	}

}

// serving file with io.Copy
// func jpg(w http.ResponseWriter, r *http.Request) {
// 	f, err := os.Open("leaf.jpg")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer f.Close()

// 	io.Copy(w, f)
// }

// serving file with http.ServeFile
// func css(w http.ResponseWriter, r *http.Request) {

// 	http.ServeFile(w, r, "styles/styles.css")

// }

func isLoggedIn(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("session")
	if err != nil {
		return false
	}
	if _, ok := inMemorySessions[cookie.Value]; ok {
		return ok
	}
	return false
}

func index(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if sessionInfo, ok := inMemorySessions[cookie.Value]; ok {
		err = tpl.ExecuteTemplate(w, "index.html", sessionInfo)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

}

func loginGet(w http.ResponseWriter, r *http.Request) {

	if isLoggedIn(w, r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	err := tpl.ExecuteTemplate(w, "login.html", nil)
	if err != nil {
		log.Fatal(err)
	}

}

func loginPost(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")

	if email == "" || password == "" {
		http.Error(w, "field can not be empty", http.StatusSeeOther)
		return
	}
	db := dbConn()
	// helper function db.Exec("USE leaf")
	// either use dbUse(db) or SQL stmt use leaf.userinfo
	// dbUse(db)
	defer db.Close()

	// check if user already exists
	var pw string
	var un string
	err := db.QueryRow("SELECT username, password FROM leaf.userinfo WHERE useremail=?", email).Scan(&un, &pw)
	if err == sql.ErrNoRows {
		// not exit in database
		http.Error(w, "user does not exist", http.StatusForbidden)
		return
	}

	// compare hashandpassword
	err = bcrypt.CompareHashAndPassword([]byte(pw), []byte(password))
	if err != nil {
		http.Error(w, "wrong password!", http.StatusForbidden)
		return
	}
	setCookieAndCreateSession(w, un, email)

	http.Redirect(w, r, "/", http.StatusSeeOther)

}

func logout(w http.ResponseWriter, r *http.Request) {
	if !isLoggedIn(w, r) {
		http.Error(w, "not authorized!", http.StatusForbidden)
		return
	}
	cookie, _ := r.Cookie("session")
	delete(inMemorySessions, cookie.Value)
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)

}

func registerGet(w http.ResponseWriter, r *http.Request) {

	if isLoggedIn(w, r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	err := tpl.ExecuteTemplate(w, "register.html", nil)
	if err != nil {
		log.Fatal(err)
	}

}

func registerPost(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	username := r.PostForm.Get("username")
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	// check user input field is empty or not.
	if email == "" || password == "" || username == "" {
		http.Error(w, "field can not be empty", http.StatusForbidden)
		return
	}

	var un string
	db := dbConn()
	// helper function db.Exec("USE leaf")
	// either use dbUse(db) or SQL stmt use leaf.userinfo
	// dbUse(db)
	defer db.Close()
	// check if user already exists
	err := db.QueryRow("SELECT username FROM leaf.userinfo WHERE username=? OR useremail=?", username, email).Scan(&un)
	// if user not exsts in DB, err = sql.ErrNoRows
	if err == sql.ErrNoRows {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Server error, unable to create you account", http.StatusInternalServerError)
			return
		}
		strPassword := string(hashedPassword)
		stmt, err := db.Prepare("INSERT INTO leaf.userinfo (username, useremail, password) VALUES (?, ?, ?)")
		if err != nil {
			log.Fatal(err)
		}
		defer stmt.Close()
		_, err = stmt.Exec(username, email, strPassword)
		if err != nil {
			log.Fatal(err)
		}
		setCookieAndCreateSession(w, username, email)

		log.Println("user created!")
		http.Redirect(w, r, "/", http.StatusSeeOther)

	} else {
		http.Error(w, "username or useremail already existed", http.StatusForbidden)
		return
	}

}
