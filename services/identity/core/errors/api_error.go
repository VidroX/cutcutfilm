package errors

type APIError struct {
	Code  string
	Error error
}
