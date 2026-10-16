# Limitations

CloudSentry is early-stage static analysis, not a cloud posture management system or a substitute for mature scanners. Only selected patterns are checked; zero findings does not imply security.

Terraform checks rely on literal parsed values. Variables, locals, modules, dynamic blocks, provider defaults, and effective policy are not resolved. Source line attribution is approximate. YAML line mapping is best effort and only top-level services documents are treated as Compose. Dockerfile checks are line-oriented and do not fully model multi-stage inheritance, build arguments, or orchestrator overrides. Findings may be false positives or false negatives. The risk score is a severity-weighted heuristic capped at 100, not a probability or compliance score. Suppression fields exist in the schema, but suppression directives are not implemented.
