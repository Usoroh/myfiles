package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"text/template"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var (
	db            *sql.DB
	err           error
	authenticated = false
)

type User struct {
	ID       int
	Username string
	Email    string
	Password string
}

type Comment struct {
	ID      int
	Content string
	Created string
	Creator string
}

type Post struct {
	ID       int
	Creator  string
	Content  string
	Created  string
	Category string
	Title    string
	Likes    int
	Dislikes int
}

type Container struct {
	Cuser     User
	Cusers    []User
	Ccomment  Comment
	Ccomments []Comment
	Cpost     Post
	Cposts    []Post
	CUsername string
	CLogged   bool
	CPostPage bool
}

type CSS struct {
	UserClassWrong string
	PwdClassWrong  string
}

func dbConn() (db *sql.DB) {
	dbDriver := "mysql"
	dbUser := "root"
	dbPass := ""
	dbName := "forum-final"
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		fmt.Println("KOOOOOOOOOL")
		panic(err.Error())
	}
	return db
}

func getPort() string {
	p := os.Getenv("PORT")
	if p != "" {
		return ":" + p
	}
	return ":9090"
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

func main() {
	fmt.Println("inside function main")
	//connect to db and create tables
	db := dbConn()
	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER AUTO_INCREMENT PRIMARY KEY, email TEXT, username TEXT, password TEXT, admin INTEGER)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS posts (postId INTEGER AUTO_INCREMENT PRIMARY KEY, userId INT, username TEXT, categoryId TEXT, title TEXT, content TEXT, created TIME, likes INT UNSIGNED DEFAULT 0, dislikes INT UNSIGNED DEFAULT 0)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS comments (commentId INTEGER AUTO_INCREMENT PRIMARY KEY, username TEXT, postId INT, content TEXT, created TIME)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS likedBy (id INTEGER AUTO_INCREMENT PRIMARY KEY, username TEXT, postId INT, liked INTEGER DEFAULT 0, disliked INTEGER DEFAULT 0)")
	statement.Exec()
	db.Close()

	static := http.FileServer(http.Dir("public"))
	http.Handle("/public/", http.StripPrefix("/public/", static))

	//declare handlers
	http.HandleFunc("/", mainPage)
	http.HandleFunc("/signup", signupPage)
	http.HandleFunc("/signin", signinPage)
	http.HandleFunc("/profile", profilePage)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/create", createPost)
	http.HandleFunc("/post", commentPost)
	http.HandleFunc("/vote", vote)

	//start the server
	fmt.Println(getPort())
	http.ListenAndServe(getPort(), nil)

}

//handle requests to main page
func mainPage(w http.ResponseWriter, r *http.Request) {
	fmt.Println("inside function mainPage")
	var c Container
	if r.Method == "GET" {

		//connect to db and retrieve posts
		db := dbConn()
		rows, err := db.Query("SELECT postId, username, categoryId, title, content, created, likes, dislikes FROM posts ORDER BY postId DESC")
		var posts []Post
		if err == nil {
			for rows.Next() {
				p := Post{}
				if err := rows.Scan(&p.ID, &p.Creator, &p.Category, &p.Title, &p.Content, &p.Created, &p.Likes, &p.Dislikes); err != nil {
					return
				}
				posts = append(posts, p)
			}
		}
		db.Close()

		//check if user is logged in
		c.Cposts = posts
		u, err := r.Cookie("username")
		if err != nil || u.Value == "" {
			fmt.Println("username cookie empty")
			c.CLogged = false
		} else {
			c.CLogged = true
			c.CUsername = u.Value
		}

		t, _ := template.ParseFiles("templates/index.html")
		t.Execute(w, c)
	}
}

func signupPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		t, _ := template.ParseFiles("templates/signup.html")
		t.Execute(w, nil)
	} else {

		//get creds and hash password
		email := r.FormValue("email")
		username := r.FormValue("username")
		password := []byte(r.FormValue("password"))
		hash, _ := bcrypt.GenerateFromPassword(password, 4)

		db := dbConn()
		statement, _ := db.Prepare("INSERT INTO users (email, username, password, admin) VALUES (?, ?, ?, ?)")
		statement.Exec(email, username, string(hash), false)
		db.Close()

		//set cookies and give session token so the user is automatically logged in
		sessionToken, _ := newUUID()
		fmt.Printf("UUIDv4: %s\n", sessionToken)

		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: time.Now().Add(600 * time.Second),
		})

		http.SetCookie(w, &http.Cookie{
			Name:    "username",
			Value:   username,
			Expires: time.Now().Add(600 * time.Second),
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func signinPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		t, _ := template.ParseFiles("templates/signin.html")
		t.Execute(w, nil)
	} else {
		//get username and password
		username := r.FormValue("username")
		password := []byte(r.FormValue("password"))
		var hashedPwd string

		db := dbConn()
		//get username, pwd from db and compare
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPwd)
		if err != nil {
			fmt.Println("username incorrect")
			class := CSS{UserClassWrong: "wrong"}
			t, _ := template.ParseFiles("templates/signin.html")
			t.Execute(w, class)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPwd), password)
		if err != nil {
			fmt.Println("password incorrect")
			class := CSS{PwdClassWrong: "wrong"}
			t, _ := template.ParseFiles("templates/signin.html")
			t.Execute(w, class)
			return
		}

		db.Close()

		//create a session token
		sessionToken, _ := newUUID()
		fmt.Printf("UUIDv4: %s\n", sessionToken)

		//set cookies
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: time.Now().Add(600 * time.Second),
		})

		http.SetCookie(w, &http.Cookie{
			Name:    "username",
			Value:   username,
			Expires: time.Now().Add(600 * time.Second),
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)

	}
}

func createPost(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		u, err := r.Cookie("username")
		if err != nil || u.Value == "" {
			fmt.Println("cannot create post unless logged id")
			http.Redirect(w, r, "/signin", http.StatusSeeOther)
		} else {
			t, _ := template.ParseFiles("templates/create.html")
			t.Execute(w, nil)
		}
	} else {
		fmt.Println("inside create")
		u, _ := r.Cookie("username")
		title := r.FormValue("title")
		content := r.FormValue("content")
		category := r.FormValue("category")
		created := time.Now()

		db := dbConn()
		statement, _ := db.Prepare("INSERT INTO posts (username, categoryId, title, content, created) VALUES (?, ?, ?, ?, ?)")
		statement.Exec(u.Value, category, title, content, created)
		db.Close()

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func profilePage(w http.ResponseWriter, r *http.Request) {

}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		//clear cookies
		cookie := &http.Cookie{
			Name:  "session_token",
			Value: "",
		}
		http.SetCookie(w, cookie)

		cookie = &http.Cookie{
			Name:  "username",
			Value: "",
		}
		http.SetCookie(w, cookie)

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func vote(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		v := r.FormValue("vote")

		post, _ := strconv.Atoi(r.FormValue("post-id"))
		u, _ := r.Cookie("username")
		username := u.Value
		fmt.Println(username)
		fmt.Println(post)

		db := dbConn()

		//if like
		if v == "Like" {
			i := -1
			fmt.Println(username, " tries to like a post")
			err := db.QueryRow("SELECT liked FROM likedby WHERE username = ? AND postId = ?", username, post).Scan(&i)
			//if error then it's the first time user likes the post
			fmt.Println(err)
			if err != nil {
				statement, e := db.Prepare("INSERT INTO likedby (username, postId, liked) VALUES (?, ?, ?)")
				fmt.Println(e)
				statement.Exec(username, post, true)
				fmt.Println("inserted")
				statement, _ = db.Prepare("UPDATE posts SET likes = likes + 1 WHERE postId = ?")
				statement.Exec(post)
			} else {
				//if i < 1 then user can like the post, if it's 1 it means he already liked the post
				fmt.Println("i is ", i)
				if i < 1 {
					//if j = 1 then user disliked a post before we have to take that dislike back
					j := -1
					db.QueryRow("SELECT disliked FROM likedby WHERE username = ? AND postId = ?", username, post).Scan(&j)
					fmt.Println("j is", j)
					if j == 1 {
						statement, _ := db.Prepare("UPDATE posts SET dislikes = dislikes - 1 WHERE postId = ?")
						statement.Exec(post)
						statement, _ = db.Prepare("UPDATE likedby SET disliked = 0 WHERE postId = ? AND username = ?")
						statement.Exec(post, username)
					}
					statement, _ := db.Prepare("UPDATE posts SET likes = likes + 1 WHERE postId = ?")
					statement.Exec(post)
					statement, _ = db.Prepare("UPDATE likedby SET liked = 1 WHERE postId = ? AND username = ?")
					statement.Exec(post, username)
				}
			}
		}

		if v == "Dislike" {
			i := -1
			fmt.Println(username, "tries to dislike a post")
			err := db.QueryRow("SELECT disliked FROM likedby WHERE username = ? AND postId = ?", username, post).Scan(&i)
			fmt.Println("dislike err", err)
			if err != nil {
				statement, _ := db.Prepare("INSERT INTO likedby (username, postId, disliked) VALUES (?, ?, ?)")
				statement.Exec(username, post, true)
				statement, _ = db.Prepare("UPDATE posts SET dislikes = dislikes + 1 WHERE postId = ?")
				statement.Exec(post)
			} else {
				//if i < 1 then user can dislike the post, if it's 1 it means he already disliked the post
				if i < 1 {
					//if j = 1 then user liked a post before we have to take that like back
					j := 1
					db.QueryRow("SELECT liked FROM likedby WHERE username = ? AND postId = ?", username, post).Scan(&j)
					if j == 1 {
						statement, _ := db.Prepare("UPDATE posts SET likes = likes - 1 WHERE postId = ?")
						statement.Exec(post)
						statement, _ = db.Prepare("UPDATE likedby SET liked = 0 WHERE postId = ? AND username = ?")
						statement.Exec(post, username)
					}
					statement, _ := db.Prepare("UPDATE posts SET dislikes = dislikes + 1 WHERE postId = ?")
					statement.Exec(post)
					statement, _ = db.Prepare("UPDATE likedby SET disliked = 1 WHERE postId = ? AND username = ?")
					statement.Exec(post, username)
				}
			}
		}
		db.Close()
		fmt.Println(r.URL)
		http.Redirect(w, r, "/", http.StatusSeeOther)

	}
}

func commentPost(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		u, _ := r.Cookie("username")
		username := u.Value

		postID, _ := strconv.Atoi(r.FormValue("post"))
		db := dbConn()
		rows, err := db.Query("SELECT postId, username, categoryId, title, content, created, likes, dislikes FROM posts WHERE postId = ? ORDER BY postId DESC", postID)
		var posts []Post
		if err == nil {
			for rows.Next() {
				p := Post{}
				if err := rows.Scan(&p.ID, &p.Creator, &p.Category, &p.Title, &p.Content, &p.Created, &p.Likes, &p.Dislikes); err != nil {
					return
				}
				posts = append(posts, p)
			}
		}
		post := posts[0]
		fmt.Println(post)

		rows, err = db.Query("SELECT commentId, username, content, created FROM comments WHERE postId = ? ORDER BY commentId DESC", postID)
		var comments []Comment
		if err == nil {
			for rows.Next() {
				c := Comment{}
				if err := rows.Scan(&c.ID, &c.Creator, &c.Content, &c.Created); err != nil {
					return
				}
				comments = append(comments, c)
			}
		}
		l := true
		if u.Value == "" {
			l = false
		}
		fmt.Println("cookie iss", u)
		container := Container{CLogged: l, Ccomments: comments, Cpost: post, CUsername: username}
		t, _ := template.ParseFiles("templates/post.html")
		t.Execute(w, container)
		db.Close()

	} else {
		content := r.FormValue("comment")
		username := r.FormValue("username")
		post := r.FormValue("post-id")

		db := dbConn()
		statement, err := db.Prepare("INSERT INTO comments (username, postId, content, created) VALUES (?, ?, ?, ?)")
		fmt.Println(err)
		statement.Exec(username, post, content, time.Now())
		db.Close()
		http.Redirect(w, r, "/post?post="+post, http.StatusSeeOther)

	}
}
