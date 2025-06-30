package redis

import (
	"context"
	"edibubble-api/config"
	"time"

	"github.com/redis/go-redis/v9"
)

type Client struct {
	client *redis.Client
	ctx    context.Context
}

func New(cfg *config.Config) *Client {
	opt, _ := redis.ParseURL(cfg.RedisURL)
	rdb := redis.NewClient(opt)
	return &Client{client: rdb, ctx: context.Background()}
}

func (c *Client) EmailSignupPending(email string) bool {
	key := "signup_pending:" + email
	exists, err := c.client.Exists(c.ctx, key).Result()
	return err == nil && exists == 1
}

func (c *Client) StoreSignupToken(token string, data map[string]string, ttl time.Duration) error {
	key := "signup_token:" + token
	pipe := c.client.TxPipeline()
	for k, v := range data {
		pipe.HSet(c.ctx, key, k, v)
	}
	pipe.Expire(c.ctx, key, ttl)
	_, err := pipe.Exec(c.ctx)
	return err
}

func (c *Client) ConsumeSignupToken(token string) (map[string]string, error) {
	key := "signup_token:" + token
	data, err := c.client.HGetAll(c.ctx, key).Result()
	if err != nil || len(data) == 0 {
		return nil, err
	}
	c.client.Del(c.ctx, key)
	return data, nil
}
