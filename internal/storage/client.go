package storage

import "github.com/ory/fosite"

type Client struct {
	ID            string
	Secret        []byte
	RedirectURIs  []string
	Scopes        []string
	GrantTypes    []string
	ResponseTypes []string
	Audience      []string
	Public        bool

	CreatedAt int64
}

func (c *Client) ToFositeClient() *fosite.DefaultClient {
	return &fosite.DefaultClient{
		ID:            c.ID,
		Secret:        c.Secret,
		RedirectURIs:  c.RedirectURIs,
		Scopes:        c.Scopes,
		GrantTypes:    c.GrantTypes,
		ResponseTypes: c.ResponseTypes,
		Audience:      c.Audience,
		Public:        c.Public,
	}
}

func FromFositeClient(fc *fosite.DefaultClient, createdAt int64) *Client {
	return &Client{
		ID:            fc.ID,
		Secret:        fc.Secret,
		RedirectURIs:  fc.RedirectURIs,
		Scopes:        fc.Scopes,
		GrantTypes:    fc.GrantTypes,
		ResponseTypes: fc.ResponseTypes,
		Audience:      fc.Audience,
		Public:        fc.Public,
		CreatedAt:     createdAt,
	}
}
