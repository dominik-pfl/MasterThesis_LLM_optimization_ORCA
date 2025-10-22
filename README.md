# MasterThesis_LLM_optimization_ORCA

This is the repo for my master thesis on evaluating LLM optimization techniques for threat to CAPEC mapping in the ORCA pipeline.

## Repository Content

This repository is structured into two main parts:

1.  **`artifact/`**: Contains the final, runnable proof-of-concept module.
2.  **`experiments/`**: Contains the Jupyter notebook and data used to conduct the research, following the CRISP-DM process.

---

### `artifact/`

This folder contains the final, self-contained RAG-based Threat-to-CAPEC mapper.

* **`ORCA_LLM_mapper.py`**: The core Python module. It can be imported and integrated into the ORCA pipeline or run standalone. It is designed to replace the original TCM component.
* **`data/input/`**: Contains the threat and CAPEC data files required to run the artifact manually. Example files are provided for testing.
* **`data/logs/`**: When run, the artifact saves the complete, raw LLM responses (including the natural language reasoning) to a JSONL file in this folder. This ensures all outputs are auditable and explainable.
* **`data/output/`**: The artifact saves its final, clean mappings to a `.csv` file in this folder. The file is formatted just like the original ORCA TCM output, with one threat-to-CAPEC ID pair per row, ready for downstream use.

### `experiments/`

This folder contains all the code, data, and results used to develop and validate the artifact.

* **`data_analysis.ipynb`**: The main Jupyter Notebook that contains all the code for the research. It follows the CRISP-DM methodology and includes all steps:
    * **Problem & Data Understanding** 
    * **Data Preparation** 
    * **Modeling** (Baseline, Prompt Engineering, and RAG implementations) 
    * **Evaluation** (Validity analysis, Jaccard similarity, etc.) 
* **`threat_data/`**: Contains the raw `all_threats.json` file from the original ORCA repository.
* **`capec_data/`**: Contains the CAPEC attack pattern data, retrieved from the MITRE CTI repository.
* **`mapped_data/`**: Contains intermediate data files generated during the analysis.
* **`results/`**: Contains all raw outputs and runtime logs from the experiments, including `evaluation_results_v2.jsonl` and `evaluation_v2.md`.

### Root Directory

* **`pyproject.toml`**: Lists all Python dependencies required to run both the experiments and the final artifact.
* **`README.md`**: This file, providing setup and usage instructions.

## How to rerun the experiments
1. Clone this repo: ```git clone https://github.com/dominik-pfl/MasterThesis_LLM_optimization_ORCA.git```
2. Install uv: ```pip install uv```
3. check if its working: ```uv``` (you should see a help menu)
4. initialize uv virtual environment: ```uv venv```
5. activate the venv: ```source .venv/bin/activate``` OR ```source .venv/Scripts/activate```
6. install the dependencies listed in pyproject.toml: ```uv sync``` OR ```python -m pip install -e .```
7. for runnning the script: set up venv as kernel for `data_analysis.ipynb` file (in vs code you might need the ipykernel add on)
8. At some point you will need ollama and the selected models. (Before installing ollama you might need to install lspci: apt install pciutils)
    a, Download ollama: ```curl -fsSL https://ollama.com/install.sh | sh``` (check ollama github repo for current version info: https://github.com/ollama/ollama )
    b, check if ollama is installed: ```which ollama``` (should output path to installation)
    c, start ollama server: ```ollama serve```
    d, download models: ```ollama pull name of model (e.g. deepseek-r1:32b)```
    e, list downloaded models: ```ollama list```
    f, run model from cmd: ```ollama run "name of model (e.g. deepseek-r1:32b)" --verbose```
9. Follow the cells in the `data_analysis.ipynb` file, they are structured by the CRISP-DM approach

## How to run the artifact
1. Clone this repo: ```git clone https://github.com/dominik-pfl/MasterThesis_LLM_optimization_ORCA.git```
2. Download ollama to run llms localls on https://ollama.com/download 
3. Download the model you want to run the artifact with (beware of hardware limitations): ```ollama pull 'name of model' ``` ('deepseek-r1:14b', 'deepseek-r1:32b', 'deepseek-r1:70b')
4. Start ollama server: ```ollama serve```
5. Install uv: ```pip install uv```
6. Create virtual environment: ```uv venv```
7. Activate the virtual environment: ```source .venv/bin/activate``` OR ```source .venv/Scripts/activate``` (depending on OS and commandline)
8. With the dependencies used in 'artifact/ORCA_LLM_mapper.py' installed, the artifact is ready to run: e.g. ```uv sync``` to sync the dependencies from pyproject.toml file
9. For a test run of the artifact navigate to the dedicated folder ```cd artifact```
10. Run the artifact with the provided test data (first three threats): ```python ORCA_LLM_mapper.py``` 
11. Inspect your results in the dedicated files inside of the ```data/output``` folder
12. For any issues open an issue within this repository: https://github.com/dominik-pfl/MasterThesis_LLM_optimization_ORCA/issues/new
