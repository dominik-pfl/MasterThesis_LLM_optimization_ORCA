import chromadb
import ollama
import pandas as pd
import re
import json
import os
import csv

def ORCA_LLM_mapper2(threat_data, capec_data, model_size='70b'):

    # --- Helper functions defined ONCE outside the loop ---
    def create_vector_db(capec_data):
        """Creates or gets a ChromaDB collection, avoiding deletion on every run."""
        client = chromadb.Client()
        # Use get_or_create_collection for efficiency
        collection = client.get_or_create_collection(
            name='capec_summaries', 
            metadata={"hnsw:space": "cosine"} # Configuration passed on creation
        )

        # Optional: You might want a way to force a rebuild if data changes
        # For this example, we assume it's created once correctly.
        if collection.count() == 0: # Only add data if the collection is empty
            print("Populating vector database...")
            collection.add(
                documents=capec_data['summary_ca_df'].tolist(),
                embeddings=capec_data['embedding'].tolist(),
                ids=capec_data['CAPEC ID'].astype(str).tolist(),
                metadatas=capec_data[['CAPEC ID']].to_dict(orient='records')
            )
        return collection

    def create_rag_prompt(threat, vector_db, k=23):
        """
        Creates the RAG prompt.
        Assumes 'threat' is a dictionary or Pandas Series for cleaner access.
        """
        # Assuming 'threat' is a dict or Series, access is cleaner
        query_embedding = threat['embedding']
        threat_summary = threat['summary']

        results = vector_db.query(
            query_embeddings=[query_embedding],
            n_results=k
        )
        
        formatted_capec_info = ""
        for doc, meta in zip(results['documents'][0], results['metadatas'][0]):
            formatted_capec_info += f"CAPEC Information for CAPEC ID {meta['CAPEC ID']}: {doc}\n"
            formatted_capec_info += "-" * 40 + "\n"
        
        prompt = f"""
This task involves mapping a threat summary from the Open Radio Access Network (O-RAN) domain to relevant attack patterns.
O-RAN represents a paradigm shift in Radio Access Network (RAN) design, moving from proprietary hardware to a more open, virtualized, and software-driven approach. It is used for mobile communication networks, particularly for 5G and future generations. Key principles of O-RAN include:
- Open System: Characterized by standardized, open interfaces to foster a multi-vendor ecosystem.
- Disaggregated RAN: Functionalities are distributed across different physical or virtual network functions.
- Software-Driven Approach: Components are deployed on white-box appliances and accelerators.
- Closed-Loop Control: Enabled by data-driven components deployed on RAN Intelligent Controllers (RICs).
Now, based on the context above, analyze the following threat summary:
{threat_summary}
Next, find the most relevant CAPECs (CAPEC stands for Common Attack Pattern Enumeration and Classification) to the the threat, from the list provided.
Go through each of the CAPECs individually:
{formatted_capec_info}
As an output, provide only a JSON array containing the selected CAPEC IDs in the form "CAPEC-ID". Do not include any explanations or additional text, only the JSON array.
"""
        return prompt

    def get_json_from_response(full_answer):
        """Extracts a JSON array string from the LLM's response."""
        match_block = re.search(r"```json\s*([\s\S]*?)\s*```", full_answer, re.DOTALL)
        if match_block:
            return match_block.group(1).strip()
        
        all_list_matches = re.findall(r'\[[\s\S]*?\]', full_answer)
        if all_list_matches:
            return all_list_matches[-1].strip()
        
        return "[]" # Return an empty JSON array string if nothing is found

    def process_response(threat, response):
        """Processes the LLM response and extracts metadata and results."""
        processed_response = {
            'threat_id': threat['Threat ID'],
            'description': threat['Threat title'],
            'tokens_per_second': round(response['eval_count'] / (response['eval_duration'] / 1e9), 2),
            'runtime': round(response['eval_duration'] / 1e9, 2),
            'prompt_token_length': response['prompt_eval_count'],
            'response_length': response['eval_count'],
            'model': response['model'],
            'timestamp': response['created_at'],
            'full_answer': response.get('response', '')
        }
        
        json_string = get_json_from_response(processed_response['full_answer'])
        
        # FIX: Parse the JSON string into a Python list
        try:
            processed_response['json_part'] = json.loads(json_string)
        except json.JSONDecodeError:
            print(f"Warning: Could not decode JSON for threat_id {threat['Threat ID']}. Found: {json_string}")
            processed_response['json_part'] = [] # Default to an empty list on failure
            
        return processed_response
    
    # --- Main Execution Logic ---
    
    # Setup CSV file
    output_dir = './data/output'
    os.makedirs(output_dir, exist_ok=True)
    csv_file_path = os.path.join(output_dir, 'mappings.csv')
    file_exists = os.path.isfile(csv_file_path)
    
    # Setup logging
    log_dir = './data/logs'
    os.makedirs(log_dir, exist_ok=True)
    jsonl_file = os.path.join(log_dir, "result_logs.jsonl")

    # Create the vector database
    collection = create_vector_db(capec_data)
    
    # FIX: Open the file once in append mode and perform all writes within this block
    with open(csv_file_path, mode='a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, delimiter=';')
        
        # Write header only if the file is new
        if not file_exists:
            writer.writerow(['Name', 'Domain','Description', 'CAPEC ID'])

        # Assuming threat_data is a pandas DataFrame, iterate over its rows
        for index, threat in threat_data.iterrows():
            print(f"Processing threat ID: {threat['Threat ID']}...")

            response_data = ollama.generate(
                model=f"deepseek-r1:{model_size}", # Note: I corrected the model name, 'deepseek-r1' is not a standard Ollama name
                prompt=create_rag_prompt(threat, collection),
                options={'seed': 42, 'temperature': 0, 'num_ctx': 8192, 'num_predict': 3000, 'top_k': 1}
            )
            
            # FIX: Correct function call with both arguments
            processed_response = process_response(threat, response_data)
            
            # Write results to CSV
            if processed_response['json_part']: # Check if list is not empty
                for capec_id in processed_response['json_part']:
                    writer.writerow([processed_response['threat_id'], 'enterprise-attack',processed_response['description'], capec_id])
                print(f"-> Added {len(processed_response['json_part'])} mappings.")
            else:
                print("-> No mappings found.")
            
            # Log the full response to a JSONL file for debugging
            with open(jsonl_file, mode='a', encoding='utf-8') as jsonl:
                jsonl.write(json.dumps(processed_response) + "\n")

    print("\nProcessing complete.")


def main():
    print("Starting ORCA LLM Mapper...")
    # Example usage
    threat_data = pd.read_pickle('./data/input/threat_data_for_RAGv2.pk1')  # Load your threat data
    threat_data = threat_data[1:3] 
    capec_data = pd.read_pickle('./data/input/capecs_for_RAG.pk1')    # Load your CAPEC data

    ORCA_LLM_mapper2(threat_data, capec_data, model_size='1.5b')

main()