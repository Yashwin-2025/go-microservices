import pandas as pd
import logging
import re
import json
from psycopg2 import sql
from typing import List, Dict, Union

def setup_logging():
    """Configure logging for the script."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def escape_windows_path(path: str) -> str:
    """
    Properly escape Windows paths for PostgreSQL JSON.
    Converts each backslash to four backslashes and handles special characters.
    """
    normalized = path.replace('\\', '/')
    escaped = normalized.replace("'", "\\'")
    return escaped

def sanitize_string(value: str, is_json: bool = False) -> str:
    """
    Sanitize string values for Cypher queries with special handling for paths.
    """
    if pd.isna(value):
        return ''
    
    value = str(value)
    
    if is_json:
        try:
            parsed_value = parse_json_string(value)
            return parsed_value.replace("'", "\\'")
        except:
            pass
    
    value = value.strip('"{}')
    
    if re.search(r'[A-Za-z]:\\|HKEY_[A-Z_]+\\', value):
        return escape_windows_path(value)
    
    return value.replace("'", "\\'")

def parse_json_string(value: str) -> str:
    """
    Parse and format JSON-like strings safely.
    """
    if pd.isna(value):
        return '{}'
    
    try:
        import ast
        parsed = ast.literal_eval(value)
        return json.dumps(parsed)
    except:
        try:
            return json.dumps(json.loads(value))
        except:
            return str(value)

def load_dataframe(filename: str, dtype: Dict = None) -> pd.DataFrame:
    """
    Safely load a CSV file into a DataFrame.
    """
    try:
        return pd.read_csv(filename, dtype=dtype or str)
    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        raise
    except Exception as e:
        logging.error(f"Error loading {filename}: {str(e)}")
        raise

def create_node_query(label: str, properties: Dict[str, str]) -> str:
    """
    Create a Cypher query for node creation with proper escaping.
    """
    json_fields = {'tags', 'manual_tags'}
    
    properties_list = []
    for k, v in properties.items():
        if not pd.isna(v):
            is_json = k in json_fields
            sanitized_value = sanitize_string(v, is_json=is_json)
            properties_list.append(f"{k}: '{sanitized_value}'")
    
    properties_str = ", ".join(properties_list)
    
    return f"""
    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:{label} {{{properties_str}}}) 
    $$) as (n agtype);
    """

def create_relationship_query(from_label: str, to_label: str, from_props: Dict[str, str], 
                            to_props: Dict[str, str], relationship: str) -> str:
    """
    Create a Cypher query for relationship creation.
    """
    from_conditions = " AND ".join(
        f"n.{k} = '{sanitize_string(v)}'" 
        for k, v in from_props.items()
        if not pd.isna(v)
    )
    
    to_conditions = " AND ".join(
        f"m.{k} = '{sanitize_string(v)}'" 
        for k, v in to_props.items()
        if not pd.isna(v)
    )

    if not from_conditions or not to_conditions:
        logging.warning(f"Missing conditions for {relationship}: from_conditions={from_conditions}, to_conditions={to_conditions}")
    
    return f"""
    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:{from_label}), (m:{to_label}) 
    WHERE {from_conditions} AND {to_conditions} 
    CREATE (n)-[:{relationship}]->(m) 
    $$) as (r agtype);
    """

def main():
    setup_logging()
    logging.info("Starting query generation...")
    
    try:
        # Load DataFrames
        vulnerabilities_df = load_dataframe("vulnerabilities.csv")
        operating_systems_df = load_dataframe("operating_systems.csv")
        evidence_df = load_dataframe("evidence.csv")
        other_os_assets_df = load_dataframe("other_os_assets.csv")
        mapping_df = load_dataframe("other_os_assets_to_vul_mapping.csv")
        
        # Create output file
        with open("cypher_queries.sql", "w", encoding='utf-8') as sql_file:
            # Create nodes
            for df, label in [
                (vulnerabilities_df, "Vulnerability"),
                (operating_systems_df, "OperatingSystem"),
                (evidence_df, "Evidence"),
                (other_os_assets_df, "Asset")
            ]:
                for _, row in df.iterrows():
                    query = create_node_query(label, row.to_dict())
                    sql_file.write(query + "\n")
            
            # Create relationships
            for _, row in mapping_df.iterrows():
                relationships = [
                    ("Asset", "Vulnerability", 
                     {"asset_id": row['asset_id']}, 
                     {"vul_id": row['vul_id']}, 
                     "HAS_VULNERABILITY"),
                    
                    ("OperatingSystem", "Asset",
                     {"os_name": row.get('os_name', '')},
                     {"asset_id": row['asset_id']},
                     "RUNS_ON"),
                    
                    ("OperatingSystem", "Vulnerability",
                     {"os_name": row.get('os_name', '')},
                     {"vul_id": row['vul_id']},
                     "HAS_VULNERABILITY")
                ]
                
                for args in relationships:
                    query = create_relationship_query(*args)
                    sql_file.write(query + "\n")
        
        logging.info("Successfully generated Cypher queries")
        
    except Exception as e:
        logging.error(f"Error during processing: {str(e)}")
        raise

if __name__ == "__main__":
    main()
