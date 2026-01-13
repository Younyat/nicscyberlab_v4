#!/bin/bash

RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'
DBNAME='../dbs/nics_cyber_lab.db'

echo -e "${RED}>>> WARNING: Deleting all Nics Cyber Lab configurations and data.${NC}"

echo -e "${YELLOW}>>> Removing database file...${NC}"
rm -f "${DBNAME}"

echo -e "${YELLOW}>>> Removing scripts and logs directories...${NC}"
rm -rf scripts/
rm -rf logs/

echo -e "${YELLOW}>>> Note: Python libraries were not removed.${NC}"

echo -e "${RED}>>> UNINSTALLATION COMPLETED.${NC}"