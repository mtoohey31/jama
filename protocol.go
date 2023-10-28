package jama

type (
	// Child Messages.

	// SetGlobal sets the Mutator that will apply to all TIDs.
	SetGlobal struct{ Mutator }
	// RemoveGlobal removes the Mutator that applies to all TIDs.
	RemoveGlobal struct{}

	// SetLocal sets the Mutator that applies to the given TID.
	SetLocal struct {
		TID int
		Mutator
	}
	// RemoveLocal removes the Mutator that applies to the given TID.
	RemoveLocal struct {
		TID int
	}

	// Parent Messages.

	// Ack indicates that the parent received the previous message.
	Ack struct{}
)
