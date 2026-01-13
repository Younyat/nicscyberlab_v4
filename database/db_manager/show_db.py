import sqlite3
from tabulate import tabulate

DB_PATH = '../dbs/nics_cyber_lab.db'

def display_table(cursor, table_name):
    print(f"\n--- TABLE: {table_name.upper()} ---")
    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()
    
    if not rows:
        print("Empty table.")
        return

    # Obtener nombres de columnas
    cursor.execute(f"PRAGMA table_info({table_name})")
    headers = [info[1] for info in cursor.fetchall()]
    
    print(tabulate(rows, headers=headers, tablefmt="grid"))

def show_all():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        tables = ["users", "instances", "scenarios", "tools", "instance_tools", "analytics_logs"]
        
        for table in tables:
            cursor.execute(f"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{table}'")
            if cursor.fetchone()[0] == 1:
                display_table(cursor, table)
            else:
                print(f"\n[!] Table '{table}' does not exist yet.")
                
        conn.close()
    except Exception as e:
        print(f"Error reading database: {e}")

if __name__ == "__main__":
    show_all()