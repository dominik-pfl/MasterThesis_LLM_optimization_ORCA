# MasterThesis_LLM_optimization_ORCA
This is the repo for my master thesis on evaluating llm optimization techniques for threat to capec mapping in the ORCA pipeline.


## How to use this repo
1. Install uv: ```pip install uv```
2. check if its working: ```uv``` (you should see a help menu)
3. initialize uv virtual environment: ```uv venv```
4. activate the venv: ```source .venv/bin/activate``` OR ```source .venv/Scripts/activate```
5. install the dependencies listed in pyproject.toml: ```uv sync``` OR ```python -m pip install -e .```
6. for runnning the script: set up venv as kernel for ipynb file (in vs code you might need the ipykernel add on)
7. At some point you will need ollama and the selected models. (Before installing ollama you might need to install lspci: apt install pciutils)
    a, Download ollama: ```curl -fsSL https://ollama.com/install.sh | sh``` (check ollama github repo for current version info: https://github.com/ollama/ollama )
    b, check if ollama is installed: ```which ollama``` (should output path to installation)
    c, start ollama server: ```ollama serve```
    d, download models: ```ollama pull name of model (e.g. deepseek-r1:32b)```
    e, list downloaded models: ```ollama list```
    f, run model from cmd: ```ollama run "name of model (e.g. deepseek-r1:32b)" --verbose```
    g, remove ollama installation: ```rm -rf $which ollama```


## How to run the artifact
1. Clone this repo: ```git clone https://github.com/dominik-pfl/MasterThesis_LLM_optimization_ORCA.git```
2. Download ollama to run llms localls on https://ollama.com/download 
3. Start ollama server: ```ollama serve```
4. Download the model you want to run the artifact with (beware of hardware limitations): ```ollama pull 'name of model' ``` ('deepseek-r1:14b', 'deepseek-r1:32b', 'deepseek-r1:70b')
5. Install uv: ```pip install uv```
6. Create virtual environment: ```uv venv```
7. Activate the virtual environment: ```source .venv/bin/activate``` OR ```source .venv/Scripts/activate``` (depending on OS and commandline)
8. With the dependencies used in 'artifact/ORCA_LLM_mapper.py' installed, the artifact is ready to run: e.g. ```uv sync``` to sync the dependencies from pyproject.toml file
9. For a test run of the artifact navigate to the dedicated folder ```cd artifact```
10. Run the artifact with the provided test data (first three threats): ```python ORCA_LLM_mapper.py``` 
11. Inspect your results in the dedicated files inside of the ```data/output``` folder
12. For any issues open an issue within this repository: https://github.com/dominik-pfl/MasterThesis_LLM_optimization_ORCA/issues/new

