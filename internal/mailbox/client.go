package mailbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"time"

	"knock/internal/identity"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
)

type Client struct {
	origin  string
	http    *http.Client
	keys    *identity.Keys
	session session
}

func NewClient(origin string, keys *identity.Keys) (*Client, error) {
	origin, err := protocol.Origin(origin)
	if err != nil {
		return nil, err
	}
	return &Client{origin: origin, keys: keys, http: &http.Client{
		Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

func (c *Client) request(ctx context.Context, method, path string, input, output any, token string) (int, error) {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, body)
	if err != nil {
		return 0, errors.New("couldn't prepare the Mailbox request")
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, errors.New("couldn't reach the Mailbox. Try again.")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		return res.StatusCode, fmt.Errorf("Mailbox returned HTTP %d", res.StatusCode)
	}
	if output != nil {
		return res.StatusCode, decode(io.LimitReader(res.Body, maxJSON+1), output)
	}
	return res.StatusCode, nil
}

func (c *Client) login(ctx context.Context) error {
	if c.keys == nil {
		return errors.New("unlock an identity to use the Mailbox inbox")
	}
	account := c.keys.Account.Bech32
	var challenge Challenge
	_, err := c.request(ctx, http.MethodPost, "/v1/auth/challenge", struct {
		Account string `json:"account"`
	}{account}, &challenge, "")
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if challenge.Version != 1 || challenge.Account != account || challenge.Origin != c.origin ||
		challenge.Nonce == (common.Hash{}) || challenge.Expires <= now || challenge.Expires > now+65 {
		return errors.New("Mailbox challenge didn't match this identity or origin")
	}
	sig, err := protocol.Sign(c.keys, authPurpose, challenge)
	if err != nil {
		return err
	}
	var established session
	_, err = c.request(ctx, http.MethodPost, "/v1/auth/session", proof{challenge, sig}, &established, "")
	if err != nil {
		return err
	}
	if len(established.Token) != 43 || established.Expires <= now || established.Expires > now+310 {
		return errors.New("invalid Mailbox session")
	}
	c.session = established
	return nil
}

func (c *Client) authenticated(ctx context.Context, method, path string, input, output any) error {
	if c.session.Expires <= time.Now().Unix()+5 {
		if err := c.login(ctx); err != nil {
			return err
		}
	}
	status, err := c.request(ctx, method, path, input, output, c.session.Token)
	if status == http.StatusUnauthorized {
		if err := c.login(ctx); err != nil {
			return err
		}
		_, err = c.request(ctx, method, path, input, output, c.session.Token)
	}
	return err
}

func (c *Client) Send(ctx context.Context, message Message) error {
	return c.authenticated(ctx, http.MethodPost, "/v1/messages", message, nil)
}

func (c *Client) Ack(ctx context.Context, id common.Hash) error {
	return c.authenticated(ctx, http.MethodPost, "/v1/messages/"+id.Hex()+"/ack", nil, nil)
}

func (c *Client) Inbox(ctx context.Context) ([]Message, error) {
	var messages []Message
	path := "/v1/inbox"
	var previous common.Hash
	for range MaxInbox / PageSize {
		var batch page
		if err := c.authenticated(ctx, http.MethodGet, path, nil, &batch); err != nil {
			return nil, err
		}
		if len(batch.Messages) > PageSize || (batch.Next != nil && len(batch.Messages) != PageSize) {
			return nil, errors.New("invalid Mailbox page")
		}
		for _, message := range batch.Messages {
			if message.Route != c.keys.Account.Bech32 || bytes.Compare(message.ID[:], previous[:]) <= 0 ||
				len(message.Body) == 0 || len(message.Body) > protocol.MaxEnvelope {
				return nil, errors.New("invalid Mailbox delivery")
			}
			previous = message.ID
		}
		messages = append(messages, batch.Messages...)
		if batch.Next == nil {
			return messages, nil
		}
		if *batch.Next != previous {
			return nil, errors.New("invalid Mailbox cursor")
		}
		path = "/v1/inbox?after=" + previous.Hex()
	}
	return nil, errors.New("Mailbox inbox exceeded its bound")
}

func (c *Client) Card(ctx context.Context, account string) (qoreseal.RecipientCard, error) {
	var card qoreseal.RecipientCard
	_, err := c.request(ctx, http.MethodGet, "/v1/cards/"+account, nil, &card, "")
	return card, err
}

func (c *Client) Publish(ctx context.Context, card qoreseal.RecipientCard) error {
	if c.keys == nil {
		return errors.New("unlock an identity to publish a recipient card")
	}
	return c.authenticated(ctx, http.MethodPut, "/v1/cards/"+c.keys.Account.Bech32, card, nil)
}

// PollDelay spreads normal inbox polling and backs off during an outage.
func PollDelay(failures int) time.Duration {
	base := time.Second << min(failures, 3)
	return base + time.Duration(rand.IntN(750))*time.Millisecond
}
