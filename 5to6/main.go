package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// Структура для хранения информации о пользователе
type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name" validate:"required,min=2,max=100"`
	Email string `json:"email" validate:"required,email"`
	Age   int    `json:"age" validate:"gte=0,lte=130"`
}

// Подключение к базе данных
func connectDB() *pg.DB {
	opt, err := pg.ParseURL("postgres://admin:admin@localhost:5432/mydb?sslmode=disable")
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	db := pg.Connect(opt)
	if db == nil {
		log.Fatalf("Failed to connect to the database.")
	}
	log.Println("Connection to the database successful.")
	return db
}

var db *pg.DB
var validate *validator.Validate

// Создание таблицы в базе данных
func createSchema() error {
	err := db.Model((*User)(nil)).CreateTable(&orm.CreateTableOptions{
		IfNotExists: true,
	})
	return err
}

// Инициализация базы данных и валидатора
func init() {
	db = connectDB()
	validate = validator.New()

	// Создание таблицы для пользователей
	err := createSchema()
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

// Получение списка пользователей с поддержкой пагинации и фильтрации
func getUsers(w http.ResponseWriter, r *http.Request) {
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")
	name := r.URL.Query().Get("name")
	ageStr := r.URL.Query().Get("age")

	page, err := strconv.Atoi(pageStr)
	if err != nil {
		page = 1
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 10
	}

	// Фильтрация по имени и возрасту
	var users []User
	query := db.Model(&users)
	if name != "" {
		query = query.Where("name = ?", name)
	}
	if ageStr != "" {
		age, _ := strconv.Atoi(ageStr)
		query = query.Where("age = ?", age)
	}

	// Пагинация
	err = query.Offset((page - 1) * limit).Limit(limit).Select()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(users)
}

// Получение конкретного пользователя по ID
func getUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id, _ := strconv.Atoi(params["id"])

	user := &User{ID: id}
	err := db.Model(user).WherePK().Select()
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(user)
}

// Создание нового пользователя
func createUser(w http.ResponseWriter, r *http.Request) {
	var user User
	_ = json.NewDecoder(r.Body).Decode(&user)

	// Валидация данных
	if err := validate.Struct(user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Сохранение в базу данных
	_, err := db.Model(&user).Insert()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(user)
}

// Обновление информации о пользователе
func updateUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id, _ := strconv.Atoi(params["id"])

	var user User
	_ = json.NewDecoder(r.Body).Decode(&user)

	// Валидация данных
	if err := validate.Struct(user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.ID = id
	_, err := db.Model(&user).Where("id = ?", id).Update()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(user)
}

// Удаление пользователя
func deleteUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id, _ := strconv.Atoi(params["id"])

	user := &User{ID: id}
	_, err := db.Model(user).WherePK().Delete()
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted"})
}

// Обработчик для авторизации
// Структура для хранения данных авторизации
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Секретный ключ для подписи токена
var jwtKey = []byte("your_secret_key") // Измените на более сложный и безопасный ключ

// Структура для представления токена
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Обработчик для авторизации
// Создаем ключ для сессии
var store = sessions.NewCookieStore([]byte("your-secret-key"))

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var authReq AuthRequest
	err := json.NewDecoder(r.Body).Decode(&authReq)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Определяем роль пользователя на основе имени и пароля
	var role string
	if authReq.Username == "admin" && authReq.Password == "adminpassword" {
		role = "admin"
	} else if authReq.Username == "user" && authReq.Password == "password" {
		role = "user"
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Создаем JWT с указанием роли
	expirationTime := time.Now().Add(30 * time.Minute)
	claims := &Claims{
		Username: authReq.Username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	// Сохранение данных о пользователе в сессии
	session, _ := store.Get(r, "session-name")
	session.Values["username"] = authReq.Username
	session.Values["role"] = role
	session.Values["authenticated"] = true
	session.Save(r, w)

	// Возвращаем токен клиенту
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func tokenValidMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Лог заголовка Authorization
		tokenString := r.Header.Get("Authorization")
		log.Println("Authorization header:", tokenString)

		if tokenString == "" || len(tokenString) < len("Bearer ") {
			http.Error(w, "Missing or malformed authorization header", http.StatusUnauthorized)
			return
		}

		// Удаление префикса "Bearer "
		tokenString = tokenString[len("Bearer "):]

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		// Логируем ошибку, если она есть
		if err != nil {
			log.Println("Error parsing token:", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Логируем результат проверки токена
		if !token.Valid {
			log.Println("Token is not valid")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Логируем успешную авторизацию
		log.Println("Token is valid for user:", claims.Username)

		// Переходим к следующему обработчику
		next.ServeHTTP(w, r)
	})
}

func roleCheckMiddleware(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Извлечение токена
			tokenString := r.Header.Get("Authorization")
			if tokenString == "" || len(tokenString) < len("Bearer ") {
				http.Error(w, "Missing or malformed authorization header", http.StatusUnauthorized)
				return
			}

			// Удаление префикса "Bearer "
			tokenString = tokenString[len("Bearer "):]

			claims := &Claims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Проверка роли
			userRole := claims.Role
			for _, role := range allowedRoles {
				if role == userRole {
					// Роль разрешена, продолжаем
					next.ServeHTTP(w, r)
					return
				}
			}

			// Если роль не разрешена
			http.Error(w, "Forbidden: You don't have access to this resource", http.StatusForbidden)
		})
	}
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/login", loginHandler).Methods("POST")

	// Защищенные маршруты для всех авторизованных пользователей
	protected := router.PathPrefix("/").Subrouter()
	protected.Use(tokenValidMiddleware)
	protected.HandleFunc("/users", getUsers).Methods("GET")
	protected.HandleFunc("/users/{id}", getUser).Methods("GET")
	protected.HandleFunc("/users", createUser).Methods("POST")
	protected.HandleFunc("/users/{id}", updateUser).Methods("PUT")
	protected.HandleFunc("/users/{id}", deleteUser).Methods("DELETE")

	// Административные маршруты, доступные только для admin
	adminProtected := router.PathPrefix("/admin").Subrouter()
	adminProtected.Use(tokenValidMiddleware, roleCheckMiddleware("admin"))
	adminProtected.HandleFunc("/admin/users", getUsers).Methods("GET") // Маршрут доступен только для admin

	log.Println("Server started at :8000")
	log.Fatal(http.ListenAndServe(":8000", router))
}
