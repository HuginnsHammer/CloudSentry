from scanner.models import Severity
from scanner.rules.dockerfile import scan_dockerfile


def test_user_in_build_stage_does_not_hide_missing_runtime_user():
    source = """FROM node:22-slim AS build
USER app
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
"""
    findings = scan_dockerfile(source, "Dockerfile")
    by_rule = {finding.rule_id: finding for finding in findings}

    assert "CS-DKR-003" in by_rule
    assert by_rule["CS-DKR-003"].line_start == 5
    assert "final stage" in by_rule["CS-DKR-003"].evidence.lower()
    assert "CS-DKR-001" not in by_rule


def test_root_user_in_build_stage_is_not_misreported_as_runtime_root():
    source = """FROM golang:1.23 AS build
USER root
RUN go build -o /out/app

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/app /app
USER nonroot
ENTRYPOINT ["/app"]
"""
    findings = scan_dockerfile(source, "Dockerfile")

    assert not any(finding.rule_id == "CS-DKR-001" for finding in findings)
    assert not any(finding.rule_id == "CS-DKR-003" for finding in findings)


def test_root_user_in_final_stage_is_detected_even_if_build_stage_is_non_root():
    source = """FROM node:22-slim AS build
USER node
RUN npm run build

FROM nginx:1.27-alpine
USER 0
COPY --from=build /app/dist /usr/share/nginx/html
"""
    findings = scan_dockerfile(source, "Dockerfile")
    root_findings = [finding for finding in findings if finding.rule_id == "CS-DKR-001"]

    assert len(root_findings) == 1
    assert root_findings[0].line_start == 6
    assert root_findings[0].severity == Severity.HIGH


def test_latest_base_image_is_reported_in_any_build_stage():
    source = """FROM node:latest AS build
RUN npm run build
FROM nginx:1.27-alpine
USER nginx
"""
    findings = scan_dockerfile(source, "Dockerfile")
    latest_findings = [finding for finding in findings if finding.rule_id == "CS-DKR-002"]

    assert len(latest_findings) == 1
    assert latest_findings[0].line_start == 1



def test_root_user_in_named_base_stage_is_inherited_by_final_stage():
    source = """FROM alpine:3.20 AS base
USER root
RUN echo build
FROM base AS runtime
CMD ["sh"]
"""
    findings = scan_dockerfile(source, "Dockerfile")
    root_findings = [finding for finding in findings if finding.rule_id == "CS-DKR-001"]

    assert len(root_findings) == 1
    assert root_findings[0].line_start == 2
    assert "inheriting" in root_findings[0].description


def test_non_root_user_in_named_base_stage_satisfies_runtime_user_check():
    source = """FROM alpine:3.20 AS base
USER app
RUN echo build
FROM base AS runtime
CMD ["sh"]
"""
    findings = scan_dockerfile(source, "Dockerfile")

    assert not any(finding.rule_id in {"CS-DKR-001", "CS-DKR-003"} for finding in findings)


def test_final_stage_user_overrides_inherited_root_user():
    source = """FROM alpine:3.20 AS base
USER root
RUN echo build
FROM base AS runtime
USER app
CMD ["sh"]
"""
    findings = scan_dockerfile(source, "Dockerfile")

    assert not any(finding.rule_id in {"CS-DKR-001", "CS-DKR-003"} for finding in findings)
