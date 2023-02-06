// Code generated by go-swagger; DO NOT EDIT.

package modelscapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// LoginResponse login response
//
// # Login request model
//
// swagger:model LoginResponse
type LoginResponse struct {

	// code
	Code int64 `json:"code,omitempty"`

	// expire
	Expire string `json:"expire,omitempty"`

	// token
	Token string `json:"token,omitempty"`
}

// Validate validates this login response
func (m *LoginResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this login response based on context it is used
func (m *LoginResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *LoginResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LoginResponse) UnmarshalBinary(b []byte) error {
	var res LoginResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
