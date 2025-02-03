import pandas as pd

# Load your CSV file into a pandas DataFrame
df = pd.read_csv("os_table.csv")  # Update the path to your CSV file
# Open a file to save the queries with UTF-8 encoding
with open("os_import.sql", "w", encoding="utf-8") as file:
    # Iterate through each row and output the cypher query string
    for _, row in df.iterrows():
        cypher_query = f"""
        SELECT * FROM cypher('os_graph', $$ 
        CREATE (:OperatingSystem {{
            os_name: '{row['os_name']}',
            os_model: '{row['os_model']}',
            os_full_name: '{row['os_full_name']}',
            os_version: '{row['os_version']}',
            os_build: '{row['os_build']}',
            os_patches: '{row['os_patches']}',
            os_install_date: '{row['os_install_date']}',
            os_autoupdate: '{row['os_autoupdate']}',
            os_vendor: '{row['os_vendor']}'
        }})
        $$) as (v agtype);
        """
        # Write the formatted query to the file
        file.write(cypher_query + "\n")  # Adding a newline for separation