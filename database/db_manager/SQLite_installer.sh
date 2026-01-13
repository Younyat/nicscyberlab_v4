#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'
DBNAME='../dbs/nics_cyber_lab.db'

echo -e "${BLUE}>>> Starting Cyber Range environment setup...${NC}"

echo -e "${BLUE}>>> Updating system and installing base packages...${NC}"
sudo apt-get update && sudo apt-get install -y python3 python3-pip sqlite3

echo -e "${BLUE}>>> Installing Python dependencies...${NC}"
pip3 install paramiko tabulate pyyaml 2>/dev/null

if [ $? -ne 0 ]; then
    pip3 install paramiko tabulate pyyaml --user --break-system-packages
fi

echo -e "${BLUE}>>> Creating directory structure...${NC}"
mkdir -p scripts/attacks scripts/detection scripts/prevention logs

echo -e "${BLUE}>>> Initializing SQLite database...${NC}"
python3 <<EOF
import sqlite3
import os

db_file = '${DBNAME}'
try:
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS instances (
            id INTEGER PRIMARY KEY, 
            name TEXT, 
            ip TEXT UNIQUE, 
            username TEXT, 
            password TEXT, 
            tools_ready INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stacks (
            id INTEGER PRIMARY KEY, 
            scenario_name TEXT, 
            attack_path TEXT, 
            detection_path TEXT, 
            prevention_path TEXT, 
            required_tools TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
except Exception as e:
    print(f"Error creating Database: {e}")
EOF

echo -e "${BLUE}>>> Verifying installation...${NC}"

ERRORS=0

if [ -f "${DBNAME}" ]; then
    echo -e "  [${GREEN}OK${NC}] Database created successfully."
else
    echo -e "  [${RED}ERROR${NC}] Database file not found."
    ERRORS=$((ERRORS+1))
fi

if [ -d "scripts/attacks" ] && [ -d "scripts/detection" ] && [ -d "scripts/prevention" ]; then
    echo -e "  [${GREEN}OK${NC}] Directory structure is ready."
else
    echo -e "  [${RED}ERROR${NC}] Some directories are missing."
    ERRORS=$((ERRORS+1))
fi

python3 -c "import paramiko, tabulate, yaml" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "  [${GREEN}OK${NC}] Python libraries installed."
else
    echo -e "  [${RED}ERROR${NC}] Missing Python libraries."
    ERRORS=$((ERRORS+1))
fi

if [ $ERRORS -eq 0 ]; then
    echo -e "\n${GREEN}>>> INSTALLATION COMPLETED SUCCESSFULLY${NC}"
else
    echo -e "\n${RED}>>> INSTALLATION FAILED WITH ${ERRORS} ERROR(S)${NC}"
    exit 1
fi