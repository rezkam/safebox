package user

import (
	"errors"
	"testing"

	domainErrors "github.com/rezkam/safebox/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockHasher is a mock type for the Hasher interface.
type MockHasher struct {
	mock.Mock
}

func (m *MockHasher) Generate(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockHasher) Verify(password, hashedPassword string) (bool, error) {
	args := m.Called(password, hashedPassword)
	return args.Bool(0), args.Error(1)
}

// MockRepository is a mock type for the Repository interface.
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) Create(entity *Entity) error {
	args := m.Called(entity)
	return args.Error(0)
}

func (m *MockRepository) FindByUsername(username string) (*Entity, error) {
	args := m.Called(username)
	entity := args.Get(0)
	if entity == nil {
		return nil, args.Error(1)
	}
	return entity.(*Entity), args.Error(1)
}

func (m *MockRepository) Update(entity *Entity) error {
	args := m.Called(entity)
	return args.Error(0)
}

func TestService_Register(t *testing.T) {
	t.Run("Successful registration", func(t *testing.T) {
		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		mockRepo.On("FindByUsername", "test-user").Return(nil, domainErrors.ErrNotFound)
		mockHasher.On("Generate", "test-password").Return("hashed-password", nil)
		mockRepo.On("Create", mock.AnythingOfType("*user.Entity")).Return(nil)

		entity, err := service.Register("test-user", "test-password")

		require.NoError(t, err)
		require.NotNil(t, entity)

		assert.Equal(t, "test-user", entity.username)
		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
	t.Run("Username already exists", func(t *testing.T) {
		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		mockRepo.On("FindByUsername", "test-user").Return(&Entity{username: "test-user"}, nil)

		entity, err := service.Register("test-user", "test-password")

		require.Error(t, err)
		require.Nil(t, entity)

		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
	t.Run("Hasher error", func(t *testing.T) {
		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		mockRepo.On("FindByUsername", "test-user").Return(nil, domainErrors.ErrNotFound)
		// Return an error when hashing the password
		mockHasher.On("Generate", "test-password").Return("", errors.New("some error"))

		entity, err := service.Register("test-user", "test-password")

		require.Error(t, err)
		require.Nil(t, entity)

		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
	t.Run("Repository error", func(t *testing.T) {
		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		mockRepo.On("FindByUsername", "test-user").Return(nil, domainErrors.ErrNotFound)
		mockHasher.On("Generate", "test-password").Return("hashed-password", nil)
		// Return an error when saving the entity
		mockRepo.On("Create", mock.AnythingOfType("*user.Entity")).Return(errors.New("some error"))

		entity, err := service.Register("test-user", "test-password")

		require.Error(t, err)
		require.Nil(t, entity)

		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
}

func TestService_Login(t *testing.T) {
	t.Run("Successful login", func(t *testing.T) {
		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		entity := &Entity{
			username:     "test-user",
			passwordHash: "hashed-password",
		}

		mockRepo.On("FindByUsername", "test-user").Return(entity, nil)
		mockHasher.On("Verify", "test-password", "hashed-password").Return(true, nil)

		result, err := service.Login("test-user", "test-password")

		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "test-user", result.username)
		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
	t.Run("User not found", func(t *testing.T) {
		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		mockRepo.On("FindByUsername", "test-user").Return(nil, domainErrors.ErrNotFound)

		result, err := service.Login("test-user", "test-password")

		require.Error(t, err)
		require.Nil(t, result)

		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
	t.Run("Invalid password", func(t *testing.T) {
		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		entity := &Entity{
			username:     "test-user",
			passwordHash: "hashed-password",
		}

		mockRepo.On("FindByUsername", "test-user").Return(entity, nil)
		mockHasher.On("Verify", "test-password", "hashed-password").Return(false, nil)

		result, err := service.Login("test-user", "test-password")

		require.Error(t, err)
		require.Nil(t, result)

		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
	t.Run("Hasher error", func(t *testing.T) {
		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		entity := &Entity{
			username:     "test-user",
			passwordHash: "hashed-password",
		}

		mockRepo.On("FindByUsername", "test-user").Return(entity, nil)
		// Return an error when verifying the password
		mockHasher.On("Verify", "test-password", "hashed-password").Return(false, errors.New("some error"))

		result, err := service.Login("test-user", "test-password")

		require.Error(t, err)
		require.Nil(t, result)

		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
}

func TestService_ChangePassword(t *testing.T) {
	t.Run("Successful password change", func(t *testing.T) {

		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		entity := &Entity{
			id:           NewID(),
			username:     "test-user",
			passwordHash: "hashed-password",
		}

		mockRepo.On("FindByUsername", "test-user").Return(entity, nil)
		mockHasher.On("Generate", "new-password").Return("new-hashed-password", nil)
		mockRepo.On("Update", entity).Return(nil)

		err := service.ChangePassword("test-user", "new-password")

		require.NoError(t, err)
		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
	t.Run("User not found", func(t *testing.T) {
		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		mockRepo.On("FindByUsername", "test-user").Return(nil, domainErrors.ErrNotFound)

		err := service.ChangePassword("test-user", "new-password")

		require.Error(t, err)
		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
	t.Run("Hasher error", func(t *testing.T) {
		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		entity := &Entity{
			id:           NewID(),
			username:     "test-user",
			passwordHash: "hashed-password",
		}

		mockRepo.On("FindByUsername", "test-user").Return(entity, nil)
		// Return an error when hashing the new password
		mockHasher.On("Generate", "new-password").Return("", errors.New("some error"))

		err := service.ChangePassword("test-user", "new-password")

		require.Error(t, err)
		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
	t.Run("Repository error", func(t *testing.T) {
		mockRepo := new(MockRepository)
		mockHasher := new(MockHasher)
		service := NewService(mockRepo, mockHasher)

		entity := &Entity{
			id:           NewID(),
			username:     "test-user",
			passwordHash: "hashed-password",
		}

		mockRepo.On("FindByUsername", "test-user").Return(entity, nil)
		mockHasher.On("Generate", "new-password").Return("new-hashed-password", nil)
		// Return an error when updating the entity
		mockRepo.On("Update", entity).Return(errors.New("some error"))

		err := service.ChangePassword("test-user", "new-password")

		require.Error(t, err)
		mockRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
}
