-- name: CreateUser :one
INSERT INTO users(id, created_at, updated_at, email, hashed_password)
VALUES (
  $1, $2, $3, $4, $5
)
RETURNING *;

-- name: RemoveUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE users.email = $1;

-- name: UpdateUserEmailPassword :one
UPDATE users
SET email = $2, hashed_password = $3, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpgradeUser :exec
UPDATE users
SET is_chirpy_red = true, updated_at = NOW()
WHERE id = $1;
