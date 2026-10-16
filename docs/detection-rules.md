# Initial detection rules

| Rule | Severity | Description | Caveat |
|---|---|---|---|
| CS-DKR-001 | High | Explicit Dockerfile USER root | Does not infer runtime overrides. |
| CS-DKR-002 | Medium | FROM image uses latest tag | Narrow tag matching. |
| CS-DKR-003 | Medium | No USER instruction | Base image or orchestrator may set a user. |
| CS-CMP-001 | Critical | Compose privileged: true | Context affects impact. |
| CS-CMP-002 | High | Compose host networking | Platform behavior varies. |
| CS-CMP-003 | Critical | Docker daemon socket mounted | Exact path match. |
| CS-CMP-004 | Medium | Wildcard host port binding | Firewall determines reachability. |
| CS-TF-001 | Critical | Public S3 ACL | Effective bucket policy can alter exposure. |
| CS-TF-002 | High | Security group rule includes 0.0.0.0/0 | Direction/protocol require review. |
| CS-TF-003 | High | EBS encryption explicitly false | Defaults and other controls are not inferred. |

Add positive and negative tests whenever changing a rule.
