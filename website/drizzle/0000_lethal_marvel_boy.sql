CREATE TABLE `certification_applications` (
	`id` text PRIMARY KEY NOT NULL,
	`organization` text NOT NULL,
	`email` text NOT NULL,
	`target` text NOT NULL,
	`requested_level` text NOT NULL,
	`summary` text NOT NULL,
	`status` text DEFAULT 'received' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
