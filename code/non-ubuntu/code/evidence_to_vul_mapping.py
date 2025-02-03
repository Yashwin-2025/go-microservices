import pandas as pd
import logging

def setup_logging():
    """Configure logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

def load_dataframe(filename: str) -> pd.DataFrame:
    """Load CSV file into a DataFrame."""
    try:
        return pd.read_csv(filename, dtype=str)
    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        raise
    except Exception as e:
        logging.error(f"Error loading {filename}: {str(e)}")
        raise

def create_relationship_query(vul_id: str) -> str:
    """Generate a Cypher query to create a relationship between Vulnerability and Evidence."""
    return f"""
    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {{vul_id: '{vul_id}'}}), (e:Evidence {{vul_id: '{vul_id}'}})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    """

def main():
    setup_logging()
    logging.info("Starting relationship generation...")

    try:
        # Load data
        vulnerabilities_df = load_dataframe("vulnerabilities.csv")
        evidence_df = load_dataframe("evidence.csv")

        # Get matching vul_id values
        common_vul_ids = set(vulnerabilities_df["vul_id"]) & set(evidence_df["vul_id"])

        # Generate and save Cypher queries
        with open("create_evidence_relationships.sql", "w", encoding="utf-8") as sql_file:
            for vul_id in common_vul_ids:
                query = create_relationship_query(vul_id)
                sql_file.write(query + "\n")

        logging.info("Successfully generated relationship queries.")

    except Exception as e:
        logging.error(f"Error during processing: {str(e)}")
        raise

if __name__ == "__main__":
    main()
