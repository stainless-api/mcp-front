package storage

import "slices"

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

func (c *Client) GetID() string              { return c.ID }
func (c *Client) GetSecret() []byte          { return c.Secret }
func (c *Client) GetRedirectURIs() []string  { return c.RedirectURIs }
func (c *Client) GetScopes() []string        { return c.Scopes }
func (c *Client) GetGrantTypes() []string    { return c.GrantTypes }
func (c *Client) GetResponseTypes() []string { return c.ResponseTypes }
func (c *Client) GetAudience() []string      { return c.Audience }
func (c *Client) IsPublic() bool             { return c.Public }

func (c *Client) clone() *Client {
	cp := *c
	cp.Secret = slices.Clone(c.Secret)
	cp.RedirectURIs = slices.Clone(c.RedirectURIs)
	cp.Scopes = slices.Clone(c.Scopes)
	cp.GrantTypes = slices.Clone(c.GrantTypes)
	cp.ResponseTypes = slices.Clone(c.ResponseTypes)
	cp.Audience = slices.Clone(c.Audience)
	return &cp
}
