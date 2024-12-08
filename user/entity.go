package user

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Type-safe identifier for a user.
type id string

// NewID generates a new id.
func NewID() id {
	return id(uuid.New().String())
}

// ParseID converts a string into an id type, validating its format.
func ParseID(raw string) (id, error) {
	_, err := uuid.Parse(raw)
	if err != nil {
		return "", errors.New("invalid id format")
	}
	return id(raw), nil
}

// Entity represents a system user.
type Entity struct {
	id           id        // Unique identifier
	username     string    // Username of the user
	passwordHash string    // Encapsulated password hash (algorithm, parameters, salt, hash)
	active       bool      // Indicates if the user is active
	createdAt    time.Time // Timestamp of creation
	updatedAt    time.Time // Timestamp of last update
}

// New creates a new Entity with cryptographic metadata.
func New(username, passwordHash string) (*Entity, error) {
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	if passwordHash == "" {
		return nil, errors.New("password hash cannot be empty")
	}

	now := time.Now().UTC()
	return &Entity{
		id:           NewID(),
		username:     username,
		passwordHash: passwordHash,
		active:       true, // Default to active
		createdAt:    now,
		updatedAt:    now,
	}, nil
}

// Activate marks the user as active.
func (u *Entity) Activate() error {
	u.active = true
	u.updatedAt = time.Now().UTC()
	return nil
}

// Deactivate marks the user as inactive.
func (u *Entity) Deactivate() error {
	u.active = false
	u.updatedAt = time.Now().UTC()
	return nil
}

// IsActive returns whether the user is active or not.
func (u *Entity) IsActive() bool {
	return u.active
}

// UpdatePassword updates the user's password hash.
func (u *Entity) UpdatePassword(newPasswordHash string) error {
	if newPasswordHash == "" {
		return errors.New("password hash cannot be empty")
	}

	u.passwordHash = newPasswordHash
	u.updatedAt = time.Now().UTC()
	return nil
}
