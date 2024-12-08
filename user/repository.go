package user

// The Repository defines the storage layer for user entities.
type Repository interface {
	Create(entity *Entity) error                     // Create a new user
	FindByUsername(username string) (*Entity, error) // Find a user by username
	Update(entity *Entity) error                     // Update user information
}
