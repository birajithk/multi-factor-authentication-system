CREATE TABLE `auth_enrollments` (
	`user_id` text PRIMARY KEY NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `auth_users`(`id`) ON UPDATE no action ON DELETE cascade
);
