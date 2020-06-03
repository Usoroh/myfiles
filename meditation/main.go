package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

func getPort() string {
	p := os.Getenv("PORT")
	if p != "" {
		return ":" + p
	}
	return ":9090"
}

func dbConn() (db *sql.DB) {
	dbDriver := "mysql"
	dbUser := "root"
	dbPass := ""
	dbName := "habits"
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		fmt.Println("KOOOOOOOOOL")
		panic(err.Error())
	}
	return db
}

type userInfo struct {
	Logged   bool
	Username string
	ID       int
	SID      string
}

type CSS struct {
	WrongUserName string
	WrongPassword string
}

type Habit struct {
	HabitUser  string
	HabitName  string
	HabitInfo  string
	HabitDays  int
	HabitTimes int
	HabitDone  int
	TimesDone  int
	Percent    float32
}

type Habits struct {
	Habits []Habit
}

var user userInfo

func main() {
	db := dbConn()

	statement, err := db.Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER AUTO_INCREMENT PRIMARY KEY, username TEXT, password TEXT, admin INTEGER)")
	if err != nil {
		fmt.Println(err)
	}
	statement.Exec()

	statement, err = db.Prepare("CREATE TABLE IF NOT EXISTS habits (id INTEGER AUTO_INCREMENT PRIMARY KEY, habit TEXT, username TEXT, info TEXT, days INTEGER, times INTEGER, daysDone INTEGER, timesDone INTEGER)")
	if err != nil {
		fmt.Println(err)
	}
	statement.Exec()

	static := http.FileServer(http.Dir("public"))
	http.Handle("/public/", http.StripPrefix("/public/", static))

	http.HandleFunc("/", mainPage)
	http.HandleFunc("/signup", signupPage)
	http.HandleFunc("/signin", signinPage)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/create", createPage)
	http.HandleFunc("/add", add)

	http.ListenAndServe(getPort(), nil)

}

func mainPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if user.Logged {

			db := dbConn()
			rows, err := db.Query("SELECT habit, username, info, days, times, daysDone, timesDone FROM habits WHERE username = ?", user.Username)
			var habits []Habit

			if err == nil {
				for rows.Next() {
					var h Habit
					if err := rows.Scan(&h.HabitName, &h.HabitUser, &h.HabitInfo, &h.HabitDays, &h.HabitTimes, &h.HabitDone, &h.TimesDone); err != nil {
						return
					}
					h.Percent = float32(h.HabitDone) / float32(h.HabitDays) * 100
					habits = append(habits, h)
				}
			}

			a := Habits{Habits: habits}
			t, _ := template.ParseFiles("templates/index.html")
			t.Execute(w, a)
		} else {
			http.Redirect(w, r, "/signin", http.StatusSeeOther)
		}
	}
}

func signupPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		t, _ := template.ParseFiles("templates/signup.html")
		t.Execute(w, nil)
	} else {
		username := r.FormValue("username")
		password := []byte(r.FormValue("password"))
		hash, _ := bcrypt.GenerateFromPassword(password, 4)

		db := dbConn()

		statement, _ := db.Prepare("INSERT INTO users (username, password, admin) VALUES (?, ?, ?)")
		statement.Exec(username, string(hash), false)
		http.Redirect(w, r, "/", http.StatusSeeOther)

	}
}

func signinPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		t, _ := template.ParseFiles("templates/signin.html")
		t.Execute(w, nil)
	} else {
		username := r.FormValue("username")
		password := []byte(r.FormValue("password"))
		var hash string

		db := dbConn()

		err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hash)
		if err != nil {
			fmt.Println("Username incorrect")
			css := CSS{WrongUserName: "wrong"}
			t, _ := template.ParseFiles("templates/signin.html")
			t.Execute(w, css)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hash), password)
		if err != nil {
			fmt.Println("Password incorrect")
			css := CSS{WrongPassword: "wrong"}
			t, _ := template.ParseFiles("templates/signin.html")
			t.Execute(w, css)
			return
		}

		sessionToken, _ := newUUID()

		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: time.Now().Add(600 * time.Second),
		})

		user.Logged = true
		user.SID = sessionToken
		user.Username = username

		http.Redirect(w, r, "http://localhost:9090/", http.StatusSeeOther)
	}
}

func createPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if user.Logged {
			t, _ := template.ParseFiles("templates/create.html")
			t.Execute(w, nil)
		} else {
			http.Redirect(w, r, "/signin", http.StatusSeeOther)
			return
		}
	} else {
		habit := r.FormValue("habit-name")
		username := user.Username
		info := r.FormValue("habit-comment")
		days := r.FormValue("habit-days")
		times := r.FormValue("habit-times")
		done := 0

		db := dbConn()
		statement, _ := db.Prepare("INSERT INTO habits (habit, username, info, days, times, daysDone, timesDone) VALUES (?, ?, ?, ?, ?, ?, ?)")
		statement.Exec(habit, username, info, days, times, done, done)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func add(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		db := dbConn()

		username := r.FormValue("habit-user")
		habit := r.FormValue("habit-name")

		statement, _ := db.Prepare("UPDATE habits SET daysDone = daysDone + 1 WHERE username = ? AND habit = ?")
		statement.Exec(username, habit)

		var daysdone int
		var days int
		var times int
		var timesdone int
		db.QueryRow("SELECT days, daysDone FROM habits WHERE username = ? AND habit = ?", username, habit).Scan(&days, &daysdone)
		db.QueryRow("SELECT times, timesDone FROM habits WHERE username = ? AND habit = ?", username, habit).Scan(&times, &timesdone)
		if daysdone == days {
			statement, _ := db.Prepare("UPDATE habits SET timesDone = timesDone + 1 WHERE username = ? AND habit = ?")
			statement.Exec(username, habit)
			statement, _ = db.Prepare("UPDATE habits SET daysDone = 0 WHERE username = ? AND habit = ?")
			statement.Exec(username, habit)
		}

		if timesdone == times {
			statement, _ := db.Prepare("UPDATE habits SET timesDone = 0 WHERE username = ? AND habit = ?")
			statement.Exec(username, habit)
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}

	http.SetCookie(w, cookie)
	user.Logged = false
	user.ID = -1
	user.Username = ""
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func newUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}
