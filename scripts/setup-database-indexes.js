// MongoDB Database Indexes Setup Script
// Run this script in MongoDB to create the required indexes for optimal performance

db = connect('mongodb://localhost:27017/smart-financial-planner');

// Users Collection Indexes
db.users.createIndex({ "email": 1 }, { unique: true, name: "email_unique" });
db.users.createIndex({ "emailVerificationToken": 1 }, { name: "email_verification_token" });
db.users.createIndex({ "passwordResetToken": 1 }, { name: "password_reset_token" });
db.users.createIndex({ "createdAt": -1 }, { name: "created_at_desc" });

print("Users collection indexes created successfully");

// Budgets Collection Indexes  
db.budgets.createIndex({ "userId": 1, "isActive": 1 }, { name: "user_active_budgets" });
db.budgets.createIndex({ "collaborators.userId": 1 }, { name: "collaborator_budgets" });
db.budgets.createIndex({ "createdAt": -1 }, { name: "budgets_created_desc" });
db.budgets.createIndex({ "userId": 1, "createdAt": -1 }, { name: "user_budgets_by_date" });

print("Budgets collection indexes created successfully");

// Expenses Collection Indexes
db.expenses.createIndex({ "userId": 1, "date": -1 }, { name: "user_expenses_by_date" });
db.expenses.createIndex({ "budgetId": 1, "category": 1 }, { name: "budget_category_expenses" });
db.expenses.createIndex({ "date": -1, "amount": -1 }, { name: "expenses_by_date_amount" });
db.expenses.createIndex({ "merchant": 1 }, { name: "expenses_by_merchant" });
db.expenses.createIndex({ "userId": 1, "category": 1, "date": -1 }, { name: "user_category_expenses" });

print("Expenses collection indexes created successfully");

// Goals Collection Indexes
db.goals.createIndex({ "userId": 1, "status": 1 }, { name: "user_goals_by_status" });
db.goals.createIndex({ "targetDate": 1, "status": 1 }, { name: "goals_by_target_date" });
db.goals.createIndex({ "userId": 1, "targetDate": 1 }, { name: "user_goals_by_date" });
db.goals.createIndex({ "userId": 1, "createdAt": -1 }, { name: "user_goals_by_created" });

print("Goals collection indexes created successfully");

// Chat Conversations Collection Indexes
db.chatconversations.createIndex({ "userId": 1, "lastMessageAt": -1 }, { name: "user_chats_by_activity" });
db.chatconversations.createIndex({ "isActive": 1 }, { name: "active_conversations" });
db.chatconversations.createIndex({ "userId": 1, "isActive": 1, "lastMessageAt": -1 }, { name: "user_active_chats" });

print("Chat conversations collection indexes created successfully");

// Notifications Collection Indexes
db.notifications.createIndex({ "userId": 1, "isRead": 1, "createdAt": -1 }, { name: "user_notifications" });
db.notifications.createIndex({ "scheduledFor": 1, "sentAt": 1 }, { name: "notification_scheduling" });
db.notifications.createIndex({ "userId": 1, "type": 1, "isRead": 1 }, { name: "user_notification_type" });

print("Notifications collection indexes created successfully");

// Reports Collection Indexes (for future implementation)
db.reports.createIndex({ "userId": 1, "type": 1, "createdAt": -1 }, { name: "user_reports" });
db.reports.createIndex({ "budgetId": 1, "period.startDate": 1 }, { name: "budget_reports_by_period" });
db.reports.createIndex({ "expiresAt": 1 }, { name: "report_expiration", expireAfterSeconds: 0 });

print("Reports collection indexes created successfully");

// Create TTL index for expired tokens (optional cleanup)
db.users.createIndex({ "passwordResetExpires": 1 }, { expireAfterSeconds: 0, name: "password_reset_expiry" });

print("All database indexes created successfully!");
print("Database is optimized for the WealthWise  application.");

// Verify indexes
print("\n=== Index Verification ===");
print("Users indexes:", db.users.getIndexes().length);
print("Budgets indexes:", db.budgets.getIndexes().length);  
print("Expenses indexes:", db.expenses.getIndexes().length);
print("Goals indexes:", db.goals.getIndexes().length);
print("Chat conversations indexes:", db.chatconversations.getIndexes().length);
print("Notifications indexes:", db.notifications.getIndexes().length);
print("Reports indexes:", db.reports.getIndexes().length);
