package jama

// Ptr returns a pointer that points to v.
func Ptr[T any](v T) *T { return &v }
