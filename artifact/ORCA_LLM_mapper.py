# -*- coding: utf-8 -*-
"""
ORCA LLM Mapper
This script uses a Retrieval-Augmented Generation (RAG) approach to map
cybersecurity threats from the O-RAN domain to the most relevant CAPEC
(Common Attack Pattern Enumeration and Classification) entries.

It performs the following steps:
1.  Loads threat data and CAPEC data (with pre-computed embeddings).
2.  Creates an in-memory vector database (ChromaDB) from the CAPEC data for efficient searching.
3.  For each threat, it queries the vector database to find the most similar CAPEC entries.
4.  Constructs a detailed prompt for a Large Language Model (LLM), providing the threat
    description and the retrieved CAPEC information as context.
5.  Sends the prompt to an Ollama-hosted LLM (e.g., DeepSeek) to get the final mapping.
6.  Parses the LLM's JSON response.
7.  Saves the resulting mappings to a versioned CSV file and logs the full LLM
    output to a versioned JSONL file for analysis and debugging.
"""

# --- Imports ---
import chromadb
import ollama
import pandas as pd
import re
import json
import os
import csv

# --- Helper Functions ---

def create_vector_db(capec_data: pd.DataFrame):
    """
    Initializes a ChromaDB vector database with CAPEC data.

    This function uses a 'get_or_create' approach, so the database is only
    populated with data the first time it's created, making subsequent
    runs faster.

    Args:
        capec_data (pd.DataFrame): DataFrame containing CAPEC summaries,
                                   embeddings, and IDs. Must have columns:
                                   'summary_ca_df', 'embedding', 'CAPEC ID'.

    Returns:
        chromadb.Collection: The ChromaDB collection object.
    """
    client = chromadb.Client()
    # Use get_or_create_collection for efficiency. The collection is created
    # only if it doesn't already exist in memory.
    collection = client.get_or_create_collection(
        name='capec_summaries',
        metadata={"hnsw:space": "cosine"}  # Using cosine similarity for semantic search
    )

    # Populate the collection only if it's empty to avoid duplicate entries on re-runs.
    if collection.count() == 0:
        print("Vector database is empty. Populating with CAPEC data...")
        collection.add(
            documents=capec_data['summary_ca_df'].tolist(),
            embeddings=capec_data['embedding'].tolist(),
            ids=capec_data['CAPEC ID'].astype(str).tolist(),
            metadatas=capec_data[['CAPEC ID']].to_dict(orient='records')
        )
        print("Population complete.")
    else:
        print("Vector database already exists and is populated.")

    return collection

def create_rag_prompt(threat: pd.Series, vector_db: chromadb.Collection, k: int = 23) -> str:
    """
    Creates the full RAG prompt for the LLM by retrieving relevant context.

    It finds the 'k' most similar CAPEC entries from the vector database based on
    the threat's embedding and formats them into a prompt.

    Args:
        threat (pd.Series): A row from the threat DataFrame, containing at least
                            'embedding' and 'summary'.
        vector_db (chromadb.Collection): The ChromaDB collection of CAPECs.
        k (int): The number of top similar CAPECs to retrieve for the context.

    Returns:
        str: The complete, formatted prompt to be sent to the LLM.
    """
    query_embedding = threat['embedding']
    threat_summary = threat['summary']

    # Query the database to find the most relevant CAPEC documents
    results = vector_db.query(
        query_embeddings=[query_embedding],
        n_results=k
    )

    # Format the retrieved CAPEC information for inclusion in the prompt
    formatted_capec_info = ""
    for doc, meta in zip(results['documents'][0], results['metadatas'][0]):
        formatted_capec_info += f"CAPEC Information for CAPEC ID {meta['CAPEC ID']}: {doc}\n"
        formatted_capec_info += "-" * 40 + "\n"

    # This prompt is the one you specified must remain unchanged.
        prompt = f"""
    This task involves mapping a threat summary from the
Open Radio Access Network (O-RAN) domain to relevant attack patterns.
O-RAN represents a paradigm shift in Radio Access Network (RAN)
design, moving from proprietary hardware to a more open,
virtualized, and software-driven approach. It is used for
mobile communication networks, particularly for 5G and future
generations. Key principles of O-RAN include:
- Open System: Characterized by standardized, open
interfaces to foster a multi-vendor ecosystem.
- Disaggregated RAN: Functionalities are distributed
across different physical or virtual network functions.
- Software-Driven Approach: Components are deployed on
white-box appliances and accelerators.
- Closed-Loop Control: Enabled by data-driven components
deployed on RAN Intelligent Controllers (RICs).
Now, based on the context above, analyze the following
threat summary:
{threat_summary}
Next, find the most relevant CAPECs (CAPEC stands for Common Attack Pattern Enumeration and Classification) to the the threat, from the list provided.
Go through each of the CAPECs individually:
{formatted_capec_info}
As an output, provide only a JSON array containing the
selected CAPEC IDs in the form "CAPEC-ID".
Do not include any explanations or additional text,
only the JSON array.
    """
    return prompt

def get_json_from_response(response_text: str) -> str:
    """
    Extracts a JSON array string from the LLM's raw text response.

    It first looks for a ```json ... ``` code block, then falls back to
    finding the last valid list-like structure '[...]' in the text.

    Args:
        response_text (str): The raw text output from the LLM.

    Returns:
        str: The extracted JSON array as a string, or an empty array "[]" if not found.
    """
    # Priority 1: Find a ```json ... ``` markdown block
    match_block = re.search(r"```json\s*([\s\S]*?)\s*```", response_text, re.DOTALL)
    if match_block:
        return match_block.group(1).strip()

    # Priority 2: Find the last occurrence of a list-like structure
    all_list_matches = re.findall(r'\[[\s\S]*?\]', response_text)
    if all_list_matches:
        return all_list_matches[-1].strip()

    # Fallback: Return an empty JSON array string if no match is found
    return "[]"

def process_llm_response(threat: pd.Series, llm_response: dict) -> dict:
    """
    Parses the full response object from Ollama into a structured dictionary.

    This function extracts performance metrics, metadata, and the final list
    of mapped CAPEC IDs.

    Args:
        threat (pd.Series): The original threat data used for the prompt.
        llm_response (dict): The complete response dictionary from `ollama.generate`.

    Returns:
        dict: A dictionary containing structured information about the run,
              including the parsed JSON part.
    """
    full_response_text = llm_response.get('response', '')
    json_string = get_json_from_response(full_response_text)

    # Safely parse the extracted JSON string into a Python list
    try:
        parsed_json = json.loads(json_string)
    except json.JSONDecodeError:
        print(f"Warning: Could not decode JSON for threat_id {threat['Threat ID']}. Found: {json_string}")
        parsed_json = []  # Default to an empty list on failure

    # Compile all relevant information into a single dictionary
    processed_data = {
        'threat_id': threat['Threat ID'],
        'description': threat['Threat title'],
        'tokens_per_second': round(llm_response.get('eval_count', 0) / (llm_response.get('eval_duration', 1) / 1e9), 2),
        'runtime_seconds': round(llm_response.get('eval_duration', 0) / 1e9, 2),
        'prompt_token_length': llm_response.get('prompt_eval_count', 0),
        'response_token_length': llm_response.get('eval_count', 0),
        'model': llm_response.get('model', 'unknown'),
        'timestamp': llm_response.get('created_at', ''),
        'mapped_capecs': parsed_json,
        'full_llm_answer': full_response_text
    }
    return processed_data


# --- Main Orchestration Function ---

def orca_llm_mapper(threat_data: pd.DataFrame, capec_data: pd.DataFrame, model_size: str, version: str):
    """
    Main function to orchestrate the threat-to-CAPEC mapping process.

    Args:
        threat_data (pd.DataFrame): DataFrame of threats to be mapped.
        capec_data (pd.DataFrame): DataFrame of CAPEC data for the knowledge base.
        version (str): A version string (e.g., "1.0", "run_002") to create
                       unique filenames for outputs.
        model_name (str): The name of the Ollama model to use (e.g., "deepseek-coder:33b").
    """
    # --- 1. Setup Directories and File Paths ---
    output_dir = './data/output'
    log_dir = './data/logs'
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    # Create versioned filenames
    csv_file_path = os.path.join(output_dir, f'mappings_v{version}.csv')
    jsonl_file_path = os.path.join(log_dir, f"result_logs_v{version}.jsonl")
    print(f"Outputting mappings to: {csv_file_path}")
    print(f"Outputting logs to: {jsonl_file_path}")

    file_exists = os.path.isfile(csv_file_path)

    # --- 2. Create Vector Database ---
    collection = create_vector_db(capec_data)

    # --- 3. Process Threats and Write Results ---
    # Open the output files once and append results in a loop
    with open(csv_file_path, mode='a', newline='', encoding='utf-8') as csvfile:
        csv_writer = csv.writer(csvfile, delimiter=';')

        # Write the header only if the file is being created
        if not file_exists:
            csv_writer.writerow(['Name', 'Domain', 'Description', 'CAPEC ID'])

        # Iterate through each threat in the input data
        for index, threat in threat_data.iterrows():
            print(f"Processing threat ID: {threat['Threat ID']}...")

            # --- 3a. Generate Prompt and Query LLM ---
            prompt = create_rag_prompt(threat, collection)
            response_data = ollama.generate(
                model=f"deepseek-r1:{model_size}",
                prompt=prompt,
                options={'seed': 42, 'temperature': 0, 'num_ctx': 8192, 'num_predict': 3000, 'top_k': 1}
            )

            # --- 3b. Process Response ---
            processed_response = process_llm_response(threat, response_data)

            # --- 3c. Write to CSV ---
            mapped_capecs = processed_response['mapped_capecs']
            if mapped_capecs:
                for capec_id in mapped_capecs:
                    csv_writer.writerow([
                        processed_response['threat_id'],
                        'enterprise-attack', # Static domain value
                        processed_response['description'],
                        capec_id
                    ])
                print(f"-> Success: Added {len(mapped_capecs)} mappings.")
            else:
                print("-> No valid mappings found in the LLM response.")

            # --- 3d. Write Full Log to JSONL for Debugging ---
            with open(jsonl_file_path, mode='a', encoding='utf-8') as jsonl:
                jsonl.write(json.dumps(processed_response) + "\n")

    print("\nProcessing complete.")


# --- Script Entry Point ---

def main():
    """
    Entry point for the script. Loads data and starts the mapping process.
    """
    # --- Configuration ---
    VERSION = "1.0"  # <--- CHANGE THIS FOR EACH RUN
    MODEL_SIZE = '1.5b' # Specify the model size here
    
    print("Starting ORCA LLM Mapper...")
    print(f"Run Version: {VERSION}")
    print(f"Using Ollama Model Size: {MODEL_SIZE}")
    # Load pre-processed threat and CAPEC data from pickle files
    try:
        threat_data = pd.read_pickle('./data/input/threat_data_for_RAG.pk1')
        capec_data = pd.read_pickle('./data/input/capecs_for_RAG.pk1')
    except FileNotFoundError as e:
        print(f"Error: Could not find input data file. {e}")
        print("Please ensure './data/input/threat_data_for_RAG.pk1' and './data/input/capecs_for_RAG.pk1' exist.")
        return

    # Slicing the dataframe for a quick test run.
    # Comment this out to run on the full dataset.
    threat_data = threat_data.head(3)
    print(f"Processing a sample of {len(threat_data)} threats.")

    # Execute the main mapping logic
    orca_llm_mapper(threat_data, capec_data, model_size=MODEL_SIZE, version=VERSION)

if __name__ == "__main__":
    main()