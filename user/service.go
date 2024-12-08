package user

import (
	"errors"

	domainErrors "github.com/rezkam/safebox/errors"
)

// Hasher defines an interface for password hashing, verification, and salt generation.
type Hasher interface {
	Generate(password string) (string, error)             // Generate a formatted password hash
	Verify(password, hashedPassword string) (bool, error) // Verify a hashed password
}

// Service encapsulates domain logic for managing users.
type Service struct {
	repo   Repository
	hasher Hasher
}

// NewService creates a new Service with dependency injection for the repository and hasher.
func NewService(repo Repository, hasher Hasher) *Service {
	return &Service{repo: repo, hasher: hasher}
}

// Register creates a new user and saves it in the repository.
func (s *Service) Register(username, password string) (*Entity, error) {
	// Check if the username already exists
	existing, err := s.repo.FindByUsername(username)
	if err != nil && !errors.Is(err, domainErrors.ErrNotFound) {
		return nil, err
	}
	if existing != nil {
		return nil, errors.New("username already exists")
	}

	// Generate the password hash
	passwordHash, err := s.hasher.Generate(password)
	if err != nil {
		return nil, err
	}

	// Create the new user entity
	entity, err := New(username, passwordHash)
	if err != nil {
		return nil, err
	}

	// Save the user to the repository
	if err := s.repo.Create(entity); err != nil {
		return nil, err
	}
	return entity, nil
}

// Login verifies the provided username and password.
func (s *Service) Login(username, password string) (*Entity, error) {
	// Retrieve the user from the repository
	entity, err := s.repo.FindByUsername(username)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, errors.New("user not found")
	}

	// Verify the password
	valid, err := s.hasher.Verify(password, entity.passwordHash)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("invalid password")
	}

	return entity, nil
}

// ChangePassword changes the password for a given user ID.
func (s *Service) ChangePassword(username, newPassword string) error {
	// Retrieve the user from the repository
	entity, err := s.repo.FindByUsername(username)
	if err != nil {
		return err
	}
	if entity == nil {
		return errors.New("user not found")
	}

	// Generate the new password hash
	newPasswordHash, err := s.hasher.Generate(newPassword)
	if err != nil {
		return err
	}

	// Update the user's password
	if err := entity.UpdatePassword(newPasswordHash); err != nil {
		return err
	}

	// Save the updated user to the repository
	return s.repo.Update(entity)
}
