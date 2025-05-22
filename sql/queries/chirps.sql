-- name: CreateChirp :one
INSERT INTO chirps(id, created_at, updated_at, body, user_id)
VALUES($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetChirps :many
SELECT * FROM chirps
ORDER BY created_at;

-- name: GetChirpsForUser :many
SELECT * FROM chirps
WHERE user_id = $1
ORDER BY created_at;

-- name: GetChirp :one
SELECT * FROM chirps
where chirps.id = $1;

-- name: RemoveChirp :exec
DELETE FROM chirps
WHERE id = $1;
