CREATE TABLE `auth_challenges` (
	`session_id` text PRIMARY KEY NOT NULL,
	`challenge` text NOT NULL,
	`mode` text NOT NULL,
	`expires` integer NOT NULL,
	FOREIGN KEY (`session_id`) REFERENCES `auth_sessions`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `auth_credentials` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`public_key` text NOT NULL,
	`counter` integer NOT NULL,
	`transports` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `auth_users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_auth_credentials_user` ON `auth_credentials` (`user_id`);--> statement-breakpoint
CREATE TABLE `auth_limits` (
	`id` text PRIMARY KEY NOT NULL,
	`count` integer NOT NULL,
	`reset` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `auth_recovery` (
	`hash` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `auth_users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_auth_recovery_user` ON `auth_recovery` (`user_id`);--> statement-breakpoint
CREATE TABLE `auth_sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`phase` text NOT NULL,
	`expires` integer NOT NULL,
	`created` integer NOT NULL,
	`auth_at` integer DEFAULT 0 NOT NULL,
	`method` text,
	`pending_totp` text,
	FOREIGN KEY (`user_id`) REFERENCES `auth_users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_auth_sessions_user` ON `auth_sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX `idx_auth_sessions_expires` ON `auth_sessions` (`expires`);--> statement-breakpoint
CREATE TABLE `auth_users` (
	`id` text PRIMARY KEY NOT NULL,
	`password_hash` text NOT NULL,
	`configured` integer DEFAULT 0 NOT NULL,
	`totp_secret` text,
	`totp_counter` integer DEFAULT -1 NOT NULL,
	`created_at` integer NOT NULL
);
