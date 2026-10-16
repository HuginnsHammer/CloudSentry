# Architecture

Pipeline: path discovery and size checks → file dispatch → safe parsing → independent rules → normalized findings → deterministic deduplication and scoring → CLI/API serialization.

The core engine does not depend on FastAPI. Terraform uses python-hcl2, YAML uses PyYAML safe_load, and Dockerfile checks inspect instruction lines without executing a build. Dynamic expressions are not evaluated. HCL line mapping is approximate because the decoded parser tree does not preserve source token locations.
