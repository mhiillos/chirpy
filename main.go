package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/mhiillos/chirpy/internal/database"
	"github.com/mhiillos/chirpy/internal/auth"
)

type apiConfig struct {
	fileServerHits atomic.Int32
	db *database.Queries
	platform string
	secret string
}

type User struct {
	Id uuid.UUID        `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email string        `json:"email"`
	Token string        `json:"token"`
}

type Chirp struct {
	Id uuid.UUID        `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email string        `json:"email"`
	Body string         `json:"body"`
	UserId uuid.UUID    `json:"user_id"`
}

// Keeping track the number of times a handler has been called
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, req)
	})
}

func healthHandler(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("content-type", "text/html")
	w.WriteHeader(200)

	metricsHTMLString := fmt.Sprintf(
	`
	<html>
		<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		</body>
	</html>
	`, cfg.fileServerHits.Load())
	w.Write(fmt.Append([]byte{}, metricsHTMLString))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, req *http.Request) {
	cfg.fileServerHits.Store(0)

	if cfg.platform != "dev" {
		respondWithError(w, 403, "Forbidden")
		return
	}
	// Dev: remove all users
	err := cfg.db.RemoveUsers(req.Context())
	if err != nil {
		respondWithError(w, 500, "Error removing users")
		return
	}
	w.WriteHeader(200)
	w.Header().Set("content-type", "text/plain")
	w.Write([]byte("Counter reset to 0!"))
}

func validateChirp(body string) (string, error) {
	if len(body) > 140 {
		return "", errors.New("Chirp too long")
	}

	// Clean the string from "bad words"
	cleanedBody := replaceBadWords(body)
	return cleanedBody, nil
}

func replaceBadWords(input string) string {
	badWords := []string{"kerfuffle", "sharbert", "fornax"}

	words := strings.Split(input, " ")
	for i, word := range words {
		if slices.Contains(badWords, strings.ToLower(word)) {
			words[i] = "****"
		}
	}
	output := strings.Join(words, " ")
	return output
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
		w.WriteHeader(code)
		type errorResponse struct {
			Error string `json:"error"`
		}
		resp := errorResponse{Error: msg}
		dat, err := json.Marshal(resp)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			return
		}
		w.Write(dat)
}

func respondWithJSON(w http.ResponseWriter, code int, payload any) {
		w.WriteHeader(code)
		dat, err := json.Marshal(payload)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			return
		}
		w.Write(dat)
}

func (cfg *apiConfig) addUserHandler(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	type requestBody struct {
		Password string `json:"password"`
		Email string    `json:"email"`
	}
	reqBody := requestBody{}
	err := decoder.Decode(&reqBody)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error decoding JSON: %s", err))
		return
	}

	hashedPassword, err := auth.HashPassword(reqBody.Password)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error hashing password: %s", err))
	}

	dbUser, err := cfg.db.CreateUser(req.Context(), database.CreateUserParams{
		ID: uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Email: reqBody.Email,
		HashedPassword: sql.NullString{
			String: hashedPassword,
			Valid:  true,
		},
	})
	if err != nil {
		respondWithError(w, 500, fmt.Sprint("Error creating user: %w", err))
		return
	}

	user := User{
		Id: dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email: dbUser.Email,
	}

	respondWithJSON(w, 201, user)
}

func (cfg *apiConfig) postChirpHandler(w http.ResponseWriter, req *http.Request) {
	type chirpBody struct {
		Body string      `json:"body"`
	}

	// Extract token
	tokenString, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "No valid token provided")
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}


	decoder := json.NewDecoder(req.Body)
	body := chirpBody{}
	err = decoder.Decode(&body)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error decoding request body: %s", err))
	}

	// Check that the Chirp is valid
	cleanedBody, err := validateChirp(body.Body)
	if err != nil {
		respondWithError(w, 400, err.Error())
		return
	}

	chirp, err := cfg.db.CreateChirp(req.Context(), database.CreateChirpParams{
		ID: uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Body: cleanedBody,
		UserID: userID,
	})
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error creating chirp: %s", err))
	}
	respondWithJSON(w, 201, Chirp{
		Id: chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body: chirp.Body,
		UserId: chirp.UserID,
	})
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, req *http.Request) {
	var chirps []Chirp
	dbChirps, err := cfg.db.GetChirps(req.Context())
	if err != nil {
		respondWithError(w, 500, "Error retrieving chirps")
		return
	}
	for _, dbChirp := range dbChirps {
		chirp := Chirp{
			Id: dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body: dbChirp.Body,
			UserId: dbChirp.UserID,
		}
		chirps = append(chirps, chirp)
	}
	respondWithJSON(w, 200, chirps)
}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("ID Could not be parsed: %s", err))
		return
	}
	chirpDb, err := cfg.db.GetChirp(req.Context(), uuid.UUID(chirpID))
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Could not find chirp: %s", err))
		return
	}
	chirp := Chirp {
		Id: chirpDb.ID,
		CreatedAt: chirpDb.CreatedAt,
		UpdatedAt: chirpDb.UpdatedAt,
		Body: chirpDb.Body,
		UserId: chirpDb.UserID,
	}
	respondWithJSON(w, 200, chirp)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, req *http.Request) {
	type requestBody struct {
		Password string      `json:"password"`
		Email string         `json:"email"`
		ExpiresInSeconds int `json:"expires_in_seconds"`
	}

	decoder := json.NewDecoder(req.Body)
	reqBody := requestBody{}
	err := decoder.Decode(&reqBody)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error decoding request body: %s", err))
		return
	}

	user, err := cfg.db.GetUserByEmail(req.Context(), reqBody.Email)
	if err != nil {
		respondWithError(w, 401, "Incorrect email or password")
		return
	}

	if !user.HashedPassword.Valid {
		respondWithError(w, 500, fmt.Sprintf("Hashed password for user %q is not valid", reqBody.Email))
		return
	}

	err = auth.CheckPasswordHash(user.HashedPassword.String, reqBody.Password)
	if err != nil {
		respondWithError(w, 401, "Incorrect email or password")
		return
	}

	expiryTimeSeconds := reqBody.ExpiresInSeconds

	// Token has duration up to one hour
	expiryTimeSeconds = min(expiryTimeSeconds, 3600)
	if expiryTimeSeconds <= 0 {
		// Default: 1 hour
		expiryTimeSeconds = 3600
	}
	tokenString, err := auth.MakeJWT(user.ID, cfg.secret, time.Duration(expiryTimeSeconds) * time.Second)
	if err != nil {
		respondWithError(w, 500, err.Error())
	}

	userResponse := User{
		Id: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
		Token: tokenString,
	}
	respondWithJSON(w, 200, userResponse)
}

func main() {
	godotenv.Load(".env")
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	secret := os.Getenv("SECRET_KEY")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	handler := http.StripPrefix("/app/", http.FileServer(http.Dir(".")))
	apiCfg := apiConfig{}
	newDb := database.New(db)
	apiCfg.db = newDb
	apiCfg.platform = platform
	apiCfg.secret = secret

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(handler))
	server := http.Server{ Handler: mux, Addr: ":8080" }

	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/users", apiCfg.addUserHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.postChirpHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)
	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)

	log.Print("Running server")
	server.ListenAndServe()
}
