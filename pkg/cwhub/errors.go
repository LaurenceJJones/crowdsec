package cwhub

import (
	"errors"
	"fmt"
)

// ErrNilRemoteHub is returned when trying to download with a local-only configuration.
var ErrNilRemoteHub = errors.New("remote hub configuration is not provided. Please report this issue to the developers")

// IndexNotFoundError is returned when the remote hub index is not found.
type IndexNotFoundError struct {
	URL    string
	Branch string
}

func (e IndexNotFoundError) Error() string {
	return fmt.Sprintf("index not found at %s, branch '%s'. Please check the .cscli.hub_branch value if you specified it in config.yaml, or use 'master' if not sure", e.URL, e.Branch)
}
