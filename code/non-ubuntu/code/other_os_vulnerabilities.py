import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import pandas as pd

def create_other_os_assets_table(csv_file_path):
    # Database connection parameters
    DB_NAME = "postgres"
    DB_USER = "postgres"
    DB_PASS = "new_secure_password"
    DB_HOST = "localhost"
    DB_PORT = "5432"

    # Connect to PostgreSQL
    try:
        # First connect to default database to create new database if it doesn't exist
        conn = psycopg2.connect(
            dbname="postgres",
            user=DB_USER,
            password=DB_PASS,
            host=DB_HOST,
            port=DB_PORT
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        
        # Check if database exists
        cur.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (DB_NAME,))
        exists = cur.fetchone()
        
        if not exists:
            # Create database if it doesn't exist
            cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(DB_NAME)))
        
        cur.close()
        conn.close()

        # Connect to the target database
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            host=DB_HOST,
            port=DB_PORT
        )
        cur = conn.cursor()

        # Load the entire CSV file into a DataFrame
        df = pd.read_csv(csv_file_path)

        # Rename columns replacing __1 with _vulnerability
        df.columns = [col.replace('__1', '_vulnerability') for col in df.columns]

        # Replace NaN values with 'placeholder'
        df.fillna('placeholder', inplace=True)

        # Create the table with dynamic columns
        columns = ', '.join(f"{col} TEXT" for col in df.columns)
        create_table_query = f"CREATE TABLE IF NOT EXISTS other_os_assets_all ({columns});"
        
        cur.execute(create_table_query)
        conn.commit()
        print("Table 'other_os_assets_all' created successfully!")

        # Write the DataFrame to the PostgreSQL table
        for row in df.itertuples(index=False):
            cur.execute(
                sql.SQL("""
                    INSERT INTO other_os_assets_all ({})
                    VALUES ({})
                """).format(
                    sql.SQL(', ').join(map(sql.Identifier, df.columns)),
                    sql.SQL(', ').join(sql.Placeholder() * len(df.columns))
                ),
                row
            )
        conn.commit()
        print(f"Data from '{csv_file_path}' loaded successfully into 'other_os_assets_all'!")

    except psycopg2.Error as e:
        print(f"An error occurred: {e}")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    create_other_os_assets_table(r'other_os_vulnerabilities.csv')
