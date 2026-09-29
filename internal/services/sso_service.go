package services

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/utils"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// SSOLogin authenticates (or, for a brand-new email, registers) a user via
// an already-verified OIDC ID token — see auth.VerifyOIDCToken, which the
// caller (handlers.SSOGoogleHandler / SSOAppleHandler) runs first.
//
// Account-linking policy, deliberately conservative:
//   - claims.EmailVerified == false is refused outright
//     (SSOEmailNotVerified), whether or not an account already exists — an
//     SSO login is only ever as trustworthy as the provider's own claim
//     that the caller controls that email address.
//   - An existing (provider, provider_user_id) identity is a normal login
//     for whatever account it's attached to.
//   - No existing identity, but a user already exists with that email:
//     refused (SSOAccountConflict) rather than silently linked.
//     Auto-linking on a verified-email match is a legitimate, common choice
//     other products make, but it merges two previously-independent
//     accounts without an explicit action from the user on either side.
//     This service asks the user to log in with their existing method
//     first instead; a "connect this provider while authenticated" flow —
//     which would perform the link with the user demonstrably in control of
//     both sides — is the natural next piece to add on top of this, not
//     implemented here.
//   - No existing identity and no existing user: a brand-new account is
//     created, with a username auto-generated from the email's local part
//     (SSO has no signup step where the user picks one).
func SSOLogin(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, provider postgres.ProviderName, origin postgres.UserOrigin, claims *auth.OIDCClaims) (*LoginResult, *utils.ErrorDetail) {
	if !claims.EmailVerified {
		utils.LogInfo(ctx, "SSO login rejected: provider email not verified", zap.String("provider", string(provider)))
		return nil, &utils.Errors.SSOEmailNotVerified
	}

	q := postgres.New(db)
	ip := utils.ClientIPFromCtx(ctx)
	ua := utils.UserAgentFromCtx(ctx)

	identity, err := q.GetIdentityByProvider(ctx, postgres.GetIdentityByProviderParams{
		Provider:       provider,
		ProviderUserID: claims.Subject,
	})
	if err == nil {
		if identity.DeletedAt.Valid || (identity.Status.Valid && (identity.Status.UserStatus == postgres.UserStatusBanned || identity.Status.UserStatus == postgres.UserStatusDisabled)) {
			utils.LogInfo(ctx, "SSO login blocked for non-usable account", zap.String("provider", string(provider)))
			return nil, &utils.Errors.AccountNotUsable
		}
		return issueLoginSession(ctx, redisClient, q, identity.UserID, identity.IdentityID, identity.Username, identity.Role, ip, ua)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		utils.LogError(ctx, "GetIdentityByProvider failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	// No identity yet for this provider — check for an email conflict
	// before creating a brand-new account.
	if _, err := q.GetUserIDByEmail(ctx, claims.Email); err == nil {
		utils.LogInfo(ctx, "SSO login rejected: email already registered under a different identity", zap.String("provider", string(provider)))
		return nil, &utils.Errors.SSOAccountConflict
	} else if !errors.Is(err, pgx.ErrNoRows) {
		utils.LogError(ctx, "GetUserIDByEmail failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	username, err := generateUniqueUsernameFromEmail(ctx, q, claims.Email)
	if err != nil {
		utils.LogError(ctx, "generateUniqueUsernameFromEmail failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	created, err := postgres.CreateSSOUserAndIdentity(ctx, db, claims.Email, username, origin, provider, claims.Subject)
	if err != nil {
		utils.LogError(ctx, "CreateSSOUserAndIdentity failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	utils.LogInfo(ctx, "New account created via SSO", zap.String("provider", string(provider)), zap.String("user_id", created.UserID.String()))

	// A freshly created user always has role 'user' (see CreateSSOUser) and
	// no lockout/status concerns yet.
	return issueLoginSession(ctx, redisClient, q, created.UserID, created.IdentityID, created.Username, postgres.UserRoleUser, ip, ua)
}

var usernameSanitizeRegexp = regexp.MustCompile(`[^a-zA-Z0-9._]`)

// generateUniqueUsernameFromEmail derives a candidate username from the
// local part of email (sanitized to fit users.username_display_format's
// constraint), falling back to a numbered suffix on collision. SSO has no
// interactive step where the user picks their own username, unlike
// email/password signup (services.CompleteEmailJoin).
func generateUniqueUsernameFromEmail(ctx context.Context, q *postgres.Queries, email string) (string, error) {
	localPart, _, found := strings.Cut(email, "@")
	if !found || localPart == "" {
		localPart = "user"
	}
	base := usernameSanitizeRegexp.ReplaceAllString(localPart, "")
	base = strings.Trim(base, "._") // format requires first/last char to be alphanumeric
	if len(base) > 24 {
		base = base[:24] // leave room for a numbered suffix under the 30-char limit
	}
	if len(base) < 2 {
		base = "user" + base
	}

	for attempt := 0; attempt < 20; attempt++ {
		candidate := base
		if attempt > 0 {
			candidate = fmt.Sprintf("%s%d", base, attempt)
		}
		taken, err := q.UsernameExists(ctx, candidate)
		if err != nil {
			return "", err
		}
		if !taken {
			return candidate, nil
		}
	}
	return "", errors.New("could not generate a unique username after 20 attempts")
}
