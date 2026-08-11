import { sql } from "drizzle-orm";
import { sqliteTable, text } from "drizzle-orm/sqlite-core";

export const certificationApplications = sqliteTable(
  "certification_applications",
  {
    id: text("id").primaryKey(),
    organization: text("organization").notNull(),
    email: text("email").notNull(),
    target: text("target").notNull(),
    requestedLevel: text("requested_level").notNull(),
    summary: text("summary").notNull(),
    status: text("status").notNull().default("received"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
);
