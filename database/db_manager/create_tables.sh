#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

DB_DIR="../dbs"
DB_NAME="$DB_DIR/nics_cyber_lab.db"

echo -e "${BLUE}>>> Starting professional database schema deployment...${NC}"

mkdir -p "$DB_DIR"

sqlite3 "$DB_NAME" <<EOF
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'trainee',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS instances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip TEXT UNIQUE NOT NULL,
    ssh_user TEXT,
    ssh_pass TEXT,
    owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    status TEXT DEFAULT 'offline',
    type TEXT DEFAULT 'general'
);

CREATE TABLE IF NOT EXISTS scenarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT CHECK(category IN ('standard', 'industrial', 'forensic', 'ai')),
    difficulty TEXT CHECK(difficulty IN ('easy', 'medium', 'hard')),
    config_path TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    category TEXT,
    version TEXT,
    install_command TEXT
);

CREATE TABLE IF NOT EXISTS instance_tools (
    instance_id INTEGER REFERENCES instances(id) ON DELETE CASCADE,
    tool_id INTEGER REFERENCES tools(id) ON DELETE CASCADE,
    installed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (instance_id, tool_id)
);

CREATE TABLE IF NOT EXISTS analytics_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    instance_id INTEGER REFERENCES instances(id),
    event_type TEXT,
    payload TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
EOF

echo -e "${BLUE}>>> Verifying table creation...${NC}"

# Lista de tablas que deben existir
REQUIRED_TABLES=("users" "instances" "scenarios" "tools" "instance_tools" "analytics_logs")
MISSING_TABLES=0

for table in "${REQUIRED_TABLES[@]}"; do
    EXISTS=$(sqlite3 "$DB_NAME" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='$table';")
    if [ "$EXISTS" -eq 1 ]; then
        echo -e "  [${GREEN}OK${NC}] Table '$table' verified."
    else
        echo -e "  [${RED}ERROR${NC}] Table '$table' is missing!"
        MISSING_TABLES=$((MISSING_TABLES + 1))
    fi
done

if [ $MISSING_TABLES -eq 0 ]; then
    echo -e "\n${GREEN}>>> DATABASE DEPLOYED AND VERIFIED SUCCESSFULLY${NC}"
else
    echo -e "\n${RED}>>> DEPLOYMENT FAILED: $MISSING_TABLES tables missing.${NC}"
    exit 1
fi