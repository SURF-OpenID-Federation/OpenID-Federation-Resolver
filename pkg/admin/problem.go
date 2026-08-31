package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const problemTypePrefix = "urn:ietf:params:oidfed:admin:problem#"

// Problem is application/problem+json as in draft-kodden-oidfed-admin-00.
type Problem struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Status  int    `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Pointer string `json:"pointer,omitempty"`
}

func problemType(token string) string {
	return problemTypePrefix + token
}

// WriteProblem writes a problem+json response and aborts.
func WriteProblem(c *gin.Context, status int, token, title, detail, pointer string) {
	if title == "" {
		title = http.StatusText(status)
	}
	c.Header("Content-Type", "application/problem+json")
	c.AbortWithStatusJSON(status, Problem{
		Type:    problemType(token),
		Title:   title,
		Status:  status,
		Detail:  detail,
		Pointer: pointer,
	})
}

// BadRequest writes 400 invalid_request.
func BadRequest(c *gin.Context, detail, pointer string) {
	WriteProblem(c, http.StatusBadRequest, "invalid_request", "Bad Request", detail, pointer)
}

// InvalidFederationClaim writes 400 invalid_federation_claim.
func InvalidFederationClaim(c *gin.Context, detail, pointer string) {
	WriteProblem(c, http.StatusBadRequest, "invalid_federation_claim", "Invalid federation claim", detail, pointer)
}

// Unauthorized writes 401 unauthorized.
func Unauthorized(c *gin.Context, detail string) {
	c.Header("WWW-Authenticate", `Bearer realm="resolver"`)
	WriteProblem(c, http.StatusUnauthorized, "unauthorized", "Unauthorized", detail, "")
}

// NotFound writes 404 not_found.
func NotFound(c *gin.Context, detail string) {
	WriteProblem(c, http.StatusNotFound, "not_found", "Not Found", detail, "")
}

// UnsupportedResource writes 404 unsupported_resource.
func UnsupportedResource(c *gin.Context, detail string) {
	WriteProblem(c, http.StatusNotFound, "unsupported_resource", "Unsupported Resource", detail, "")
}

// Conflict writes 409.
func Conflict(c *gin.Context, token, detail string) {
	if token == "" {
		token = "conflict"
	}
	WriteProblem(c, http.StatusConflict, token, "Conflict", detail, "")
}

// PreconditionFailed writes 412.
func PreconditionFailed(c *gin.Context, detail string) {
	WriteProblem(c, http.StatusPreconditionFailed, "precondition_failed", "Precondition Failed", detail, "")
}

// ServerError writes 500.
func ServerError(c *gin.Context, detail string) {
	WriteProblem(c, http.StatusInternalServerError, "internal", "Internal Server Error", detail, "")
}
