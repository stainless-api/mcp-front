package jsonrpc

// Standard JSON-RPC 2.0 error codes
const (
	ParseError     = -32700 // Invalid JSON was received by the server
	InvalidRequest = -32600 // The JSON sent is not a valid Request object
	MethodNotFound = -32601 // The method does not exist / is not available
	InvalidParams  = -32602 // Invalid method parameter(s)
	InternalError  = -32603 // Internal JSON-RPC error
)

// errorMessages maps error codes to standard messages
var errorMessages = map[int]string{
	ParseError:     "Parse error",
	InvalidRequest: "Invalid request",
	MethodNotFound: "Method not found",
	InvalidParams:  "Invalid params",
	InternalError:  "Internal error",
}

// NewError creates a new JSON-RPC error with the given code and message
func NewError(code int, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// NewErrorWithData creates a new JSON-RPC error with additional data
func NewErrorWithData(code int, message string, data any) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Data:    data,
	}
}

// NewStandardError creates a new JSON-RPC error using standard error messages
func NewStandardError(code int) *Error {
	message, ok := errorMessages[code]
	if !ok {
		message = "Unknown error"
	}
	return &Error{
		Code:    code,
		Message: message,
	}
}
