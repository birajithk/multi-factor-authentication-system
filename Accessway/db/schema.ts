import { sqliteTable, text, integer, index } from 'drizzle-orm/sqlite-core';

export const users = sqliteTable('auth_users', {
  id: text('id').primaryKey(),
  passwordHash: text('password_hash').notNull(),
  configured: integer('configured').notNull().default(0),
  totpSecret: text('totp_secret'),
  totpCounter: integer('totp_counter').notNull().default(-1),
  createdAt: integer('created_at').notNull(),
});
export const sessions = sqliteTable('auth_sessions', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  phase: text('phase').notNull(),
  expires: integer('expires').notNull(),
  created: integer('created').notNull(),
  authAt: integer('auth_at').notNull().default(0),
  method: text('method'),
  pendingTotp: text('pending_totp'),
}, table => [index('idx_auth_sessions_user').on(table.userId), index('idx_auth_sessions_expires').on(table.expires)]);
export const credentials = sqliteTable('auth_credentials', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  publicKey: text('public_key').notNull(),
  counter: integer('counter').notNull(),
  transports: text('transports').notNull(),
}, table => [index('idx_auth_credentials_user').on(table.userId)]);
export const challenges = sqliteTable('auth_challenges', {
  sessionId: text('session_id').primaryKey().references(() => sessions.id, { onDelete: 'cascade' }),
  challenge: text('challenge').notNull(),
  mode: text('mode').notNull(),
  expires: integer('expires').notNull(),
});
export const recovery = sqliteTable('auth_recovery', {
  hash: text('hash').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
}, table => [index('idx_auth_recovery_user').on(table.userId)]);
export const limits = sqliteTable('auth_limits', {
  id: text('id').primaryKey(),
  count: integer('count').notNull(),
  reset: integer('reset').notNull(),
});
// Committed with the initial factors, preventing concurrent double enrollment.
export const enrollments = sqliteTable('auth_enrollments', {
  userId: text('user_id').primaryKey().references(() => users.id, { onDelete: 'cascade' }),
});
