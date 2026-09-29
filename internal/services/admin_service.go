package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"auth-api/config"
	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/emailer"
	"auth-api/internal/utils"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/resend/resend-go/v2"
	"go.uber.org/zap"
)

// Package-level policy for the admin API surface:
//
//   - An actor can never target their own account through this API
//     (CannotTargetSelf) — self-ban, self-demote, and self-delete are all
//     exactly the kind of mistake, or the exact move a compromised admin
//     session would make, this exists to rule out entirely.
//   - No action here may target an account that already has the 'admin'
//     role (AdminProtected), regardless of the acting admin's own role.
//     This mirrors trg_prevent_admin_demotion/trg_prevent_admin_deletion
//     (003_prevent_triggers.up.sql), which block demoting or deleting an
//     admin unconditionally at the database level with no actor-based
//     exception — this API keeps that same unconditional stance for every
//     admin-affecting action, not just the two the database itself
//     enforces. Changing or removing an admin account is deliberately left
//     to direct database access, not this API.
//
// Role gating itself (moderator+ vs admin-only) lives at the router layer
// (internal/handlers/admin.go's requireRole), matching how
// open-route-vs-protected-route auth is already decided at the router
// layer rather than re-checked in every service function.

const (
	defaultAdminPageLimit = 25
	maxAdminPageLimit     = 100
)

// AdminUser is the shape returned by the user-listing/detail admin
// endpoints: a deliberately narrower view than the full users row (no
// password/session internals), but with everything an admin/moderator
// needs to identify and act on an account.
type AdminUser struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	Role        string `json:"role"`
	CreatedAt   string `json:"created_at"`
	LastLogin   string `json:"last_login,omitempty"`
	DeletedAt   string `json:"deleted_at,omitempty"`
}

// AdminListUsersParams are the (already-untyped) filters accepted from
// query params; empty strings mean "don't filter on this".
type AdminListUsersParams struct {
	Search string
	Status string
	Role   string
	Limit  int
	Offset int
}

type AdminListUsersResult struct {
	Users []AdminUser `json:"users"`
	Total int64       `json:"total"`
}

// ListUsers returns a paginated, optionally filtered view of every user
// account (moderator+).
func ListUsers(ctx context.Context, db *pgxpool.Pool, params AdminListUsersParams) (*AdminListUsersResult, *utils.ErrorDetail) {
	limit := params.Limit
	if limit <= 0 || limit > maxAdminPageLimit {
		limit = defaultAdminPageLimit
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	var statusFilter postgres.NullUserStatus
	if s := strings.TrimSpace(params.Status); s != "" {
		parsed, ok := parseUserStatus(s)
		if !ok {
			return nil, &utils.Errors.InvalidPayload
		}
		statusFilter = postgres.NullUserStatus{UserStatus: parsed, Valid: true}
	}
	var roleFilter postgres.NullUserRole
	if r := strings.TrimSpace(params.Role); r != "" {
		parsed, ok := parseUserRole(r)
		if !ok {
			return nil, &utils.Errors.InvalidRole
		}
		roleFilter = postgres.NullUserRole{UserRole: parsed, Valid: true}
	}
	search := textOrNull(strings.TrimSpace(params.Search))

	q := postgres.New(db)
	rows, err := q.ListUsers(ctx, postgres.ListUsersParams{
		Search: search, Status: statusFilter, Role: roleFilter,
		PageLimit: int32(limit), PageOffset: int32(offset),
	})
	if err != nil {
		utils.LogError(ctx, "ListUsers failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	total, err := q.CountUsers(ctx, postgres.CountUsersParams{Search: search, Status: statusFilter, Role: roleFilter})
	if err != nil {
		utils.LogError(ctx, "CountUsers failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	users := make([]AdminUser, 0, len(rows))
	for _, row := range rows {
		users = append(users, AdminUser{
			ID: row.ID.String(), Email: row.Email, Username: row.Username, DisplayName: row.UsernameDisplay,
			Status: string(row.Status.UserStatus), Role: string(row.Role),
			CreatedAt: formatTimestamptz(row.CreatedAt), LastLogin: formatTimestamptz(row.LastLogin), DeletedAt: formatTimestamptz(row.DeletedAt),
		})
	}
	return &AdminListUsersResult{Users: users, Total: total}, nil
}

// GetUser returns the admin-facing detail view of a single account,
// including soft-deleted ones (moderator+).
func GetUser(ctx context.Context, db *pgxpool.Pool, targetUserID string) (*AdminUser, *utils.ErrorDetail) {
	targetPG, ok := parseUserID(targetUserID)
	if !ok {
		return nil, &utils.Errors.UserNotFound
	}
	q := postgres.New(db)
	row, err := q.GetUserByIDAdmin(ctx, targetPG)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &utils.Errors.UserNotFound
		}
		utils.LogError(ctx, "GetUserByIDAdmin failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	return adminUserFromRow(row), nil
}

// BanUser sets an account's status to banned and revokes every session on
// it (moderator+). See package doc for the self-target/admin-target rules.
func BanUser(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, actorID, actorUsername, targetUserID, reason string) *utils.ErrorDetail {
	return setUserStatusAction(ctx, db, redisClient, actorID, actorUsername, targetUserID, reason,
		postgres.UserStatusBanned, postgres.AuditActionUserBan, true, "User banned by admin")
}

// UnbanUser restores a banned account to active (moderator+). Sessions
// were already destroyed by the ban; there's nothing to revoke here.
func UnbanUser(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, actorID, actorUsername, targetUserID, reason string) *utils.ErrorDetail {
	return setUserStatusAction(ctx, db, redisClient, actorID, actorUsername, targetUserID, reason,
		postgres.UserStatusActive, postgres.AuditActionUserUnban, false, "User unbanned by admin")
}

// DisableUser sets an account's status to disabled and revokes every
// session on it (moderator+). Distinct from a ban in intent (e.g. a
// suspected-compromised or self-requested deactivation rather than a
// punitive action), but identical in mechanism.
func DisableUser(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, actorID, actorUsername, targetUserID, reason string) *utils.ErrorDetail {
	return setUserStatusAction(ctx, db, redisClient, actorID, actorUsername, targetUserID, reason,
		postgres.UserStatusDisabled, postgres.AuditActionChangeStatus, true, "User disabled by admin")
}

// EnableUser restores a disabled account to active (moderator+).
func EnableUser(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, actorID, actorUsername, targetUserID, reason string) *utils.ErrorDetail {
	return setUserStatusAction(ctx, db, redisClient, actorID, actorUsername, targetUserID, reason,
		postgres.UserStatusActive, postgres.AuditActionChangeStatus, false, "User enabled by admin")
}

// setUserStatusAction is the shared implementation behind Ban/Unban/Disable/Enable —
// they differ only in the target status, the audit action recorded, and
// whether sessions need revoking.
func setUserStatusAction(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, actorID, actorUsername, targetUserID, reason string,
	status postgres.UserStatus, action postgres.AuditAction, revokeSessions bool, logMsg string) *utils.ErrorDetail {
	q := postgres.New(db)
	target, targetPG, errDetail := loadAdminTarget(ctx, q, actorID, targetUserID)
	if errDetail != nil {
		return errDetail
	}

	var sessionIDs []pgtype.UUID
	if revokeSessions {
		var err error
		sessionIDs, err = q.ListActiveSessionIDs(ctx, targetPG)
		if err != nil {
			utils.LogWarn(ctx, "ListActiveSessionIDs failed; Postgres sessions will still be revoked, but their Redis entries may outlive them", zap.Error(err))
		}
	}

	actorPG, _ := parseUserID(actorID)
	ip, ua := auditRequestMeta(ctx)
	reasonText := textOrNull(strings.TrimSpace(reason))

	err := postgres.WithActor(ctx, db, actorID, func(qtx *postgres.Queries) error {
		if err := qtx.SetUserStatus(ctx, postgres.SetUserStatusParams{
			Status: postgres.NullUserStatus{UserStatus: status, Valid: true}, ID: targetPG,
		}); err != nil {
			return err
		}
		if revokeSessions {
			if err := qtx.RevokeAllUserSessions(ctx, targetPG); err != nil {
				return err
			}
		}
		return qtx.CreateAuditLog(ctx, postgres.CreateAuditLogParams{
			ActorID: actorPG, ActorUsername: textOrNull(actorUsername),
			TargetUserID: targetPG, TargetUsername: textOrNull(target.Username), TargetEmail: textOrNull(target.Email),
			Action: action, Reason: reasonText, Ip: ip, UserAgent: ua,
		})
	})
	if err != nil {
		utils.LogError(ctx, "admin status-change transaction failed", zap.Error(err), zap.String("action", string(action)))
		return &utils.Errors.InternalServerError
	}

	for _, sessionID := range sessionIDs {
		if err := auth.DeleteSession(ctx, sessionID.String(), redisClient); err != nil {
			utils.LogWarn(ctx, "Failed to delete Redis session after admin status change", zap.Error(err), zap.String("session_id", sessionID.String()))
		}
	}

	utils.LogInfo(ctx, logMsg, zap.String("actor_id", actorID), zap.String("target_user_id", targetUserID))
	return nil
}

// ForceLogoutUser revokes every session on an account without changing its
// status (moderator+) — e.g. in response to a user reporting a lost
// device, where the account itself isn't in question.
func ForceLogoutUser(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, actorID, actorUsername, targetUserID, reason string) *utils.ErrorDetail {
	q := postgres.New(db)
	target, targetPG, errDetail := loadAdminTarget(ctx, q, actorID, targetUserID)
	if errDetail != nil {
		return errDetail
	}

	sessionIDs, err := q.ListActiveSessionIDs(ctx, targetPG)
	if err != nil {
		utils.LogWarn(ctx, "ListActiveSessionIDs failed; Postgres sessions will still be revoked, but their Redis entries may outlive them", zap.Error(err))
	}

	actorPG, _ := parseUserID(actorID)
	ip, ua := auditRequestMeta(ctx)
	reasonText := textOrNull(strings.TrimSpace(reason))
	if reasonText.String == "" {
		reasonText = pgtype.Text{String: "All sessions revoked by admin", Valid: true}
	}

	err = postgres.WithActor(ctx, db, actorID, func(qtx *postgres.Queries) error {
		if err := qtx.RevokeAllUserSessions(ctx, targetPG); err != nil {
			return err
		}
		return qtx.CreateAuditLog(ctx, postgres.CreateAuditLogParams{
			ActorID: actorPG, ActorUsername: textOrNull(actorUsername),
			TargetUserID: targetPG, TargetUsername: textOrNull(target.Username), TargetEmail: textOrNull(target.Email),
			Action: postgres.AuditActionAdminNote, Reason: reasonText, Ip: ip, UserAgent: ua,
		})
	})
	if err != nil {
		utils.LogError(ctx, "ForceLogoutUser transaction failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	for _, sessionID := range sessionIDs {
		if err := auth.DeleteSession(ctx, sessionID.String(), redisClient); err != nil {
			utils.LogWarn(ctx, "Failed to delete Redis session after admin force-logout", zap.Error(err), zap.String("session_id", sessionID.String()))
		}
	}

	utils.LogInfo(ctx, "User force-logged-out by admin", zap.String("actor_id", actorID), zap.String("target_user_id", targetUserID))
	return nil
}

// ChangeUserRole promotes or demotes a user between 'user' and 'moderator'
// (admin-only, enforced at the router). Demoting/promoting a target that
// is already 'admin' is refused by loadAdminTarget, and
// trg_prevent_admin_demotion independently refuses the same at the
// database level regardless.
func ChangeUserRole(ctx context.Context, db *pgxpool.Pool, actorID, actorUsername, targetUserID, newRole string) *utils.ErrorDetail {
	role, ok := parseUserRole(newRole)
	if !ok {
		return &utils.Errors.InvalidRole
	}

	q := postgres.New(db)
	target, targetPG, errDetail := loadAdminTarget(ctx, q, actorID, targetUserID)
	if errDetail != nil {
		return errDetail
	}
	if role == postgres.UserRoleAdmin {
		// Promoting a user straight to admin through a generic role-change
		// endpoint is deliberately out of scope — see package doc.
		return &utils.Errors.AdminProtected
	}

	actorPG, _ := parseUserID(actorID)
	ip, ua := auditRequestMeta(ctx)

	err := postgres.WithActor(ctx, db, actorID, func(qtx *postgres.Queries) error {
		if err := qtx.SetUserRole(ctx, postgres.SetUserRoleParams{Role: role, ID: targetPG}); err != nil {
			return err
		}
		return qtx.CreateAuditLog(ctx, postgres.CreateAuditLogParams{
			ActorID: actorPG, ActorUsername: textOrNull(actorUsername),
			TargetUserID: targetPG, TargetUsername: textOrNull(target.Username), TargetEmail: textOrNull(target.Email),
			Action: postgres.AuditActionChangeRole, Reason: textOrNull("Role changed to " + string(role) + " by admin"), Ip: ip, UserAgent: ua,
		})
	})
	if err != nil {
		utils.LogError(ctx, "ChangeUserRole transaction failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	utils.LogInfo(ctx, "User role changed by admin", zap.String("actor_id", actorID), zap.String("target_user_id", targetUserID), zap.String("new_role", string(role)))
	return nil
}

// DeleteUser soft-deletes an account (sets deleted_at) and revokes every
// session on it (admin-only, enforced at the router). This is a soft
// delete, not the hard DELETE trg_prevent_admin_deletion guards against —
// loadAdminTarget's blanket admin-target refusal is what actually protects
// admin accounts from this path.
func DeleteUser(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, actorID, actorUsername, targetUserID, reason string) *utils.ErrorDetail {
	q := postgres.New(db)
	target, targetPG, errDetail := loadAdminTarget(ctx, q, actorID, targetUserID)
	if errDetail != nil {
		return errDetail
	}

	sessionIDs, err := q.ListActiveSessionIDs(ctx, targetPG)
	if err != nil {
		utils.LogWarn(ctx, "ListActiveSessionIDs failed; Postgres sessions will still be revoked, but their Redis entries may outlive them", zap.Error(err))
	}

	actorPG, _ := parseUserID(actorID)
	ip, ua := auditRequestMeta(ctx)
	reasonText := textOrNull(strings.TrimSpace(reason))

	err = postgres.WithActor(ctx, db, actorID, func(qtx *postgres.Queries) error {
		if err := qtx.SoftDeleteUser(ctx, targetPG); err != nil {
			return err
		}
		if err := qtx.RevokeAllUserSessions(ctx, targetPG); err != nil {
			return err
		}
		return qtx.CreateAuditLog(ctx, postgres.CreateAuditLogParams{
			ActorID: actorPG, ActorUsername: textOrNull(actorUsername),
			TargetUserID: targetPG, TargetUsername: textOrNull(target.Username), TargetEmail: textOrNull(target.Email),
			Action: postgres.AuditActionUserDeleted, Reason: reasonText, Ip: ip, UserAgent: ua,
		})
	})
	if err != nil {
		utils.LogError(ctx, "DeleteUser transaction failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	for _, sessionID := range sessionIDs {
		if err := auth.DeleteSession(ctx, sessionID.String(), redisClient); err != nil {
			utils.LogWarn(ctx, "Failed to delete Redis session after admin delete", zap.Error(err), zap.String("session_id", sessionID.String()))
		}
	}

	utils.LogInfo(ctx, "User soft-deleted by admin", zap.String("actor_id", actorID), zap.String("target_user_id", targetUserID))
	return nil
}

// AdminResetUserPassword sends a password-reset email to a user on an
// admin/moderator's behalf (moderator+) — e.g. a support request from a
// user who can no longer receive codes some other way. Unlike
// RequestPasswordReset (the public, unauthenticated endpoint), this is
// already targeted at a real, admin-selected account, so the
// enumeration-resistance tradeoffs that shape that function's responses
// don't apply here: a bad target ID just returns UserNotFound.
func AdminResetUserPassword(ctx context.Context, db *pgxpool.Pool, resendClient *resend.Client, actorID, actorUsername, targetUserID string) *utils.ErrorDetail {
	q := postgres.New(db)
	target, targetPG, errDetail := loadAdminTarget(ctx, q, actorID, targetUserID)
	if errDetail != nil {
		return errDetail
	}

	rawToken, err := auth.RandomToken(32)
	if err != nil {
		utils.LogError(ctx, "Failed to generate admin-initiated password reset token", zap.Error(err))
		return &utils.Errors.InternalServerError
	}
	if _, err := q.CreatePasswordReset(ctx, postgres.CreatePasswordResetParams{
		UserID:     targetPG,
		ResetToken: auth.HashOpaqueToken(rawToken),
		ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(config.Loaded.PasswordResetTTL), Valid: true},
		Source:     postgres.ResetSourceAdmin,
	}); err != nil {
		utils.LogError(ctx, "Failed to create admin-initiated password reset record", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	actorPG, _ := parseUserID(actorID)
	ip, ua := auditRequestMeta(ctx)
	if err := postgres.New(db).CreateAuditLog(ctx, postgres.CreateAuditLogParams{
		ActorID: actorPG, ActorUsername: textOrNull(actorUsername),
		TargetUserID: targetPG, TargetUsername: textOrNull(target.Username), TargetEmail: textOrNull(target.Email),
		Action: postgres.AuditActionAdminNote, Reason: textOrNull("Password reset link sent by admin"), Ip: ip, UserAgent: ua,
	}); err != nil {
		utils.LogWarn(ctx, "Failed to write admin audit log for password reset", zap.Error(err))
	}

	if _, err := emailer.SendPasswordResetEmail(rawToken, target.Email, resendClient); err != nil {
		utils.LogError(ctx, "Failed to send admin-initiated password reset email", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	utils.LogInfo(ctx, "Password reset initiated by admin", zap.String("actor_id", actorID), zap.String("target_user_id", targetUserID))
	return nil
}

type AuditLogEntry struct {
	ID             string          `json:"id"`
	ActorID        string          `json:"actor_id,omitempty"`
	ActorUsername  string          `json:"actor_username,omitempty"`
	ActorEmail     string          `json:"actor_email,omitempty"`
	TargetUserID   string          `json:"target_user_id,omitempty"`
	TargetUsername string          `json:"target_username,omitempty"`
	TargetEmail    string          `json:"target_email,omitempty"`
	Action         string          `json:"action"`
	Changes        json.RawMessage `json:"changes,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	IP             string          `json:"ip,omitempty"`
	UserAgent      string          `json:"user_agent,omitempty"`
	CreatedAt      string          `json:"created_at"`
}

type AdminListAuditLogsResult struct {
	Entries []AuditLogEntry `json:"entries"`
	Total   int64           `json:"total"`
}

// ListAuditLogs returns a paginated view of the audit log, optionally
// filtered to a single target user (moderator+).
func ListAuditLogs(ctx context.Context, db *pgxpool.Pool, targetUserID string, limit, offset int) (*AdminListAuditLogsResult, *utils.ErrorDetail) {
	if limit <= 0 || limit > maxAdminPageLimit {
		limit = defaultAdminPageLimit
	}
	if offset < 0 {
		offset = 0
	}

	var targetFilter pgtype.UUID
	if targetUserID != "" {
		parsed, ok := parseUserID(targetUserID)
		if !ok {
			return nil, &utils.Errors.UserNotFound
		}
		targetFilter = parsed
	}

	q := postgres.New(db)
	rows, err := q.ListAuditLogs(ctx, postgres.ListAuditLogsParams{
		TargetUserID: targetFilter, PageLimit: int32(limit), PageOffset: int32(offset),
	})
	if err != nil {
		utils.LogError(ctx, "ListAuditLogs failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	total, err := q.CountAuditLogs(ctx, targetFilter)
	if err != nil {
		utils.LogError(ctx, "CountAuditLogs failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	entries := make([]AuditLogEntry, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, AuditLogEntry{
			ID: row.ID.String(), ActorID: uuidOrEmpty(row.ActorID),
			ActorUsername: row.ActorUsername.String, ActorEmail: row.ActorEmail.String,
			TargetUserID: uuidOrEmpty(row.TargetUserID), TargetUsername: row.TargetUsername.String, TargetEmail: row.TargetEmail.String,
			Action: string(row.Action), Changes: json.RawMessage(row.Changes), Reason: row.Reason.String,
			IP: row.Ip.String, UserAgent: row.UserAgent.String, CreatedAt: formatTimestamptz(row.CreatedAt),
		})
	}
	return &AdminListAuditLogsResult{Entries: entries, Total: total}, nil
}

// loadAdminTarget fetches the target user and enforces the two blanket
// rules every admin mutation shares — see the package doc comment above.
func loadAdminTarget(ctx context.Context, q *postgres.Queries, actorID, targetUserID string) (postgres.GetUserByIDAdminRow, pgtype.UUID, *utils.ErrorDetail) {
	targetPG, ok := parseUserID(targetUserID)
	if !ok {
		return postgres.GetUserByIDAdminRow{}, pgtype.UUID{}, &utils.Errors.UserNotFound
	}
	if actorPG, ok := parseUserID(actorID); ok && actorPG.Bytes == targetPG.Bytes {
		return postgres.GetUserByIDAdminRow{}, pgtype.UUID{}, &utils.Errors.CannotTargetSelf
	}

	target, err := q.GetUserByIDAdmin(ctx, targetPG)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return postgres.GetUserByIDAdminRow{}, pgtype.UUID{}, &utils.Errors.UserNotFound
		}
		utils.LogError(ctx, "GetUserByIDAdmin failed", zap.Error(err))
		return postgres.GetUserByIDAdminRow{}, pgtype.UUID{}, &utils.Errors.InternalServerError
	}
	if target.Role == postgres.UserRoleAdmin {
		return postgres.GetUserByIDAdminRow{}, pgtype.UUID{}, &utils.Errors.AdminProtected
	}
	return target, targetPG, nil
}

func adminUserFromRow(row postgres.GetUserByIDAdminRow) *AdminUser {
	return &AdminUser{
		ID: row.ID.String(), Email: row.Email, Username: row.Username, DisplayName: row.UsernameDisplay,
		Status: string(row.Status.UserStatus), Role: string(row.Role),
		CreatedAt: formatTimestamptz(row.CreatedAt), LastLogin: formatTimestamptz(row.LastLogin), DeletedAt: formatTimestamptz(row.DeletedAt),
	}
}

func parseUserStatus(s string) (postgres.UserStatus, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "active":
		return postgres.UserStatusActive, true
	case "offline":
		return postgres.UserStatusOffline, true
	case "disabled":
		return postgres.UserStatusDisabled, true
	case "banned":
		return postgres.UserStatusBanned, true
	default:
		return "", false
	}
}

func parseUserRole(s string) (postgres.UserRole, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "user":
		return postgres.UserRoleUser, true
	case "moderator":
		return postgres.UserRoleModerator, true
	case "admin":
		return postgres.UserRoleAdmin, true
	default:
		return "", false
	}
}

func auditRequestMeta(ctx context.Context) (pgtype.Text, pgtype.Text) {
	return textOrNull(utils.ClientIPFromCtx(ctx)), textOrNull(utils.UserAgentFromCtx(ctx))
}

func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

func formatTimestamptz(t pgtype.Timestamptz) string {
	if !t.Valid {
		return ""
	}
	return t.Time.Format(time.RFC3339)
}

func uuidOrEmpty(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return id.String()
}
