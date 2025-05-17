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
	RefreshToken string `json:"refresh_token"`
}

type Chirp struct {
	Id uuid.UUID        `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email string        `json:"email"`
	Body string         `json:"body"`
	UserId uuid.UUID    `json:"user_id"`
}

type Token struct {
	Token string `json:"token"`
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
		return
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
		return
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
		return
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
		respondWithError(w, 404, fmt.Sprintf("Chirp not found"))
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

	// Generate access token
	tokenString, err := auth.MakeJWT(user.ID, cfg.secret, 1*time.Hour)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}

	// Generate refresh token
	refreshTokenString, _ := auth.MakeRefreshToken()
	token, err := cfg.db.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
		Token: refreshTokenString,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		UserID: user.ID,
		ExpiresAt: time.Now().Add(60*24*time.Hour),
		RevokedAt: sql.NullTime{},
	})
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error adding refresh token to database: %s", err))
		return
	}

	userResponse := User{
		Id: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
		Token: tokenString,
		RefreshToken: token.Token,
	}
	respondWithJSON(w, 200, userResponse)
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, req *http.Request) {
	refreshTokenString, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("Error fetching refresh token: %s", err))
		return
	}

	token, err := cfg.db.GetRefreshToken(req.Context(), refreshTokenString)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("Refresh token does not exist: %s", err))
		return
	}

	if token.ExpiresAt.Before(time.Now()) || token.RevokedAt.Valid {
		respondWithError(w, 401, "Refresh token has expired")
		return
	}

	accessToken, err := auth.MakeJWT(token.UserID, cfg.secret, 1*time.Hour)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("Error creating access token: %s", err))
		return
	}

	tokenResponse := Token{Token: accessToken}
	respondWithJSON(w, 200, tokenResponse)
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, req *http.Request) {
	refreshTokenString, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("Error fetching refresh token: %s", err))
		return
	}

	err = cfg.db.RevokeToken(req.Context(), refreshTokenString)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("Error revoking refresh token: %s", err))
		return
	}

	respondWithJSON(w, 204, nil)
}

// Handler for updating email/password
func (cfg *apiConfig) putUsersHandler(w http.ResponseWriter, req *http.Request) {
	accessToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("Error fetching access token: %s", err))
		return
	}

	// Verify user
	userID, err := auth.ValidateJWT(accessToken, cfg.secret)
	if err != nil {
		respondWithError(w, 401, "Invalid access token")
		return
	}

	type requestBody struct {
		Password string `json:"password"`
		Email string    `json:"email"`
	}

	var reqBody requestBody
	decoder := json.NewDecoder(req.Body)
	err = decoder.Decode(&reqBody)
	if err != nil {
		respondWithError(w, 500, "Error unpacking request, expected 'email' and 'password' fields")
		return
	}

	// Hash the new password
	hashedPassword, err := auth.HashPassword(reqBody.Password)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error hashing password: %s", err))
		return
	}

	updatedUser, err := cfg.db.UpdateUserEmailPassword(req.Context(), database.UpdateUserEmailPasswordParams{
		ID: userID,
		Email: reqBody.Email,
		HashedPassword: sql.NullString{
			String: hashedPassword,
			Valid: true, },
	})
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error updating user: %s", err))
		return
	}

	type response struct {
		ID string           `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email string        `json:"email"`
	}

	respondWithJSON(w, 200, response{
		ID: updatedUser.ID.String(),
		CreatedAt: updatedUser.CreatedAt,
		UpdatedAt: updatedUser.UpdatedAt,
		Email: updatedUser.Email,
	})
}

// Handler to delete a chirp
func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))

	// Authenticate user
	authTokenString, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("Error fetching bearer token: %s", err))
		return
	}

	userID, err := auth.ValidateJWT(authTokenString, cfg.secret)
	if err != nil {
		respondWithError(w, 401, "Invalid token")
		return
	}

	chirp, err := cfg.db.GetChirp(req.Context(), uuid.UUID(chirpID))
	if err != nil {
		respondWithError(w, 404, "Chirp not found")
		return
	}

	if chirp.UserID != userID {
		respondWithError(w, 403, "User is not authorized to remove chirp")
		return
	}

	// Remove the chirp
	err = cfg.db.RemoveChirp(req.Context(), chirp.ID)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error removing chirp: %s", err))
		return
	}

	respondWithJSON(w, 204, nil)
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
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.putUsersHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)

	log.Print("Running server")
	server.ListenAndServe()
}
