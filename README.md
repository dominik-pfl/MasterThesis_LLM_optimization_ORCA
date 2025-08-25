# MasterThesis_LLM_optimization_ORCA
This is the repo for my master thesis on evaluating llm optimization techniques for threat to capec mapping in the ORCA pipeline.


## How to use this repo
1. Install uv: pip install uv
2. check if its working: uv (you should see a help menu)
3. initialize uv virtual environment: uv venv
4. activate the venv: source .venv/bin/activate
5. install the dependencies listed in pyproject.toml: uv sync OR python -m pip install -e .
6. for runnning the script: set up venv as kernel for ipynb file (in vs code you might need the ipykernel add on)
7. At some point you will need ollama and the selected models. (Before installing ollama you might need to install lspci: apt install pciutils)
    a, Download ollama: curl -fsSL https://ollama.com/install.sh | OLLAMA_VERSION=0.11.6 sh (check ollama github repo for current version info: https://github.com/ollama/ollama )
    b, check if ollama is installed: which ollama (should output path to installation)
    c, start ollama server: ollama serve
    d, download models: ollama pull "name of model (e.g. deepseek-r1:32b)"
    e, run model from cmd: ollama run "name of model (e.g. deepseek-r1:32b)" --verbose
    f, remove ollama installation: rm -rf $which ollama
