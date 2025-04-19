This repo hosts the code for Vela, a project focused on evaluating and modeling the performance of smartNICs. Below is an overview of the repository structure and its key components:

## Repository Structure

### `eval/`
This directory contains evaluation-related code. It includes:
- Applications such as `natlb` and `mcrouter` running on two types of smartNICs.
- Demonstrations and evaluations of state migration functionality on Netronome smartNICs.
- Scripts and configurations for setting up and running performance tests.

### `perf_model/`
This directory contains code related to the roofline performance model. It provides:
- Tools to build and analyze the roofline model on two types of smartNICs.
- Scripts for collecting performance metrics and visualizing the results.

### Additional Directories
<!-- - `docs/`: Contains documentation and supplementary materials for understanding and using the repository.
- `scripts/`: Includes utility scripts for automating tasks such as environment setup and data processing. -->
- `configs/`: Stores configuration files required for various experiments and models.

## Purpose
The repository aims to provide tools and code for:
1. Evaluating smartNIC performance through real-world applications and state migration tests.
2. Modeling smartNIC capabilities using the roofline performance model to gain insights into their computational and memory bandwidth limits.