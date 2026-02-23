package subscription

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler handles subscription selection requests.
type Handler struct {
	selector *Selector
}

// NewHandler creates a new subscription handler.
func NewHandler(selector *Selector) *Handler {
	return &Handler{
		selector: selector,
	}
}

// SelectSubscription handles POST /v1/subscriptions/select requests.
//
// This endpoint is called by Authorino during AuthPolicy evaluation to determine
// which subscription a user should be assigned to. The request contains authenticated
// user information (groups, username) from auth.identity and an optional explicit
// subscription name from the X-MaaS-Subscription header.
//
// Selection logic:
//  1. If requestedSubscription is provided, validate user has access and return it
//  2. Otherwise, auto-select the highest priority subscription the user belongs to
//
// This endpoint is protected by NetworkPolicy and should only be accessible from
// Authorino pods. No additional authentication is needed as the groups/username
// come from an already-authenticated auth.identity object.
func (h *Handler) SelectSubscription(c *gin.Context) {
	var req SelectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "bad_request",
			Message: "invalid request body: " + err.Error(),
		})
		return
	}

	response, err := h.selector.Select(req.Groups, req.Username, req.RequestedSubscription)
	if err != nil {
		var noSubErr *NoSubscriptionError
		var notFoundErr *SubscriptionNotFoundError
		var accessDeniedErr *AccessDeniedError

		if errors.As(err, &noSubErr) {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "not_found",
				Message: err.Error(),
			})
			return
		}

		if errors.As(err, &notFoundErr) {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "not_found",
				Message: err.Error(),
			})
			return
		}

		if errors.As(err, &accessDeniedErr) {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Error:   "access_denied",
				Message: err.Error(),
			})
			return
		}

		// All other errors are internal server errors
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "failed to select subscription: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}
