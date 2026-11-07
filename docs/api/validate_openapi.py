"""Validate the fixed OAS document and sanitized real HTTP response samples.

Requires PyYAML, jsonschema and openapi-spec-validator (test tools only).
Optionally set PYTHONPATH to a workspace-local installation of those packages.
"""
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from openapi_schema_validator import OAS30Validator, oas30_format_checker
from openapi_spec_validator import validate_spec
from referencing import Registry, Resource

def route_template(path):
    return re.sub(r"^/api/v1/devices/[0-9]+", "/api/v1/devices/{device_id}", urlsplit(path).path)


def validate_response(spec, route, method, status, body, validator, formats, uri):
    response = spec["paths"][route][method]["responses"][str(status)]
    assert "schema" in response["content"]["application/json"]
    registry = Registry().with_resource(
        uri, Resource.from_contents({"$schema": "https://json-schema.org/draft/2020-12/schema", **spec})
    )
    escaped_route = route.replace("~", "~0").replace("/", "~1")
    schema = {"$ref": f"{uri}#/paths/{escaped_route}/{method}/responses/{status}/content/application~1json/schema"}
    validator(schema, registry=registry, format_checker=formats).validate(body)


root = Path(__file__).resolve().parents[2]
spec = yaml.safe_load((root / "docs/api/openapi.yaml").read_text(encoding="utf-8"))
validate_spec(spec)
assert spec["openapi"] == "3.1.1"
count = 0
samples_path = root / "docs/acceptance/topology-api-2026-11-02/response-samples.json"
samples = json.loads(samples_path.read_text(encoding="utf-8"))
for sample in samples:
    route = route_template(sample["path"])
    if sample["status"] == 429 and route.startswith("/api/v1/topology"):
        continue  # Historical fixture from before removal of the per-Key limit.
    validate_response(spec, route, sample.get("method", "get"), sample["status"], sample["body"],
                      Draft202012Validator, FormatChecker(), "urn:gonet:openapi")
    count += 1
for route, item in spec["paths"].items():
    if route.startswith(("/api/v1/topology", "/api/v1/devices")):
        assert item["get"]["security"] == [{"SessionCookie": []}, {"AgentBearer": []}]
        if "head" in item:
            assert all("content" not in value for value in item["head"]["responses"].values())
for route, item in spec["paths"].items():
    if route.startswith("/api/v1/admin/"):
        for method, operation in item.items():
            assert operation["security"] == [{"SessionCookie": []}]
            if method in {"post", "patch", "delete"}:
                assert {"$ref": "#/components/parameters/CSRF"} in operation["parameters"]
agent = yaml.safe_load((root / "docs/api/agent-openapi.yaml").read_text(encoding="utf-8"))
validate_spec(agent)
assert agent["openapi"] == "3.0.3"
assert set(agent["paths"]) == {
    "/api/v1/devices",
    "/api/v1/devices/{device_id}",
    "/api/v1/devices/{device_id}/neighbors",
    "/api/v1/devices/{device_id}/interfaces",
    "/api/v1/devices/{device_id}/uplink-path",
    "/api/v1/topology/summary",
    "/api/v1/topology/collection",
}
agent_count = 0
precise = json.loads((root / "docs/acceptance/precise-topology-response-samples.json").read_text(encoding="utf-8"))
for sample in precise:
    route = route_template(sample["path"])
    validate_response(spec, route, "get", sample["status"], sample["body"],
                      Draft202012Validator, FormatChecker(), "urn:gonet:openapi")
    if route in agent["paths"]:
        validate_response(agent, route, "get", sample["status"], sample["body"],
                          OAS30Validator, oas30_format_checker, "urn:gonet:agent")
        agent_count += 1

for route, item in agent["paths"].items():
    assert set(item) == {"get"}
    assert item["get"]["security"] == [{"AgentBearer": []}]
    for status, response in item["get"]["responses"].items():
        if "content" not in response:
            continue
        for example in response["content"]["application/json"].get("examples",{}).values():
            validate_response(agent, route, "get", status, example["value"],
                              OAS30Validator, oas30_format_checker, "urn:gonet:agent")

v2_count = 0
for sample_file in sorted((root / "docs/acceptance/gonet-uplink-optimization").glob("P[235]-http.json")):
    for sample in json.loads(sample_file.read_text(encoding="utf-8")):
        route = route_template(sample["path"])
        validate_response(spec, route, "get", sample["status"], sample["body"],
                          Draft202012Validator, FormatChecker(), "urn:gonet:openapi")
        validate_response(agent, route, "get", sample["status"], sample["body"],
                          OAS30Validator, oas30_format_checker, "urn:gonet:agent")
        v2_count += 1

print(f"PASS OpenAPI 3.1.1 with {count} historical and {len(precise)} precise HTTP responses")
print(f"PASS OpenAPI 3.0.3 with {agent_count} precise HTTP responses and documented examples")
print(f"PASS both OpenAPI contracts with {v2_count} schema-v2 HTTP responses")

lag_samples = root / "docs/acceptance/gonet-lag-adaptation/http-samples.json"
if lag_samples.exists():
    values = json.loads(lag_samples.read_text(encoding="utf-8"))
    for sample in values:
        route = route_template(sample["path"])
        validate_response(spec, route, "get", sample["status"], sample["body"],
                          Draft202012Validator, FormatChecker(), "urn:gonet:openapi")
        validate_response(agent, route, "get", sample["status"], sample["body"],
                          OAS30Validator, oas30_format_checker, "urn:gonet:agent")
    print(f"PASS both OpenAPI contracts with {len(values)} LAG schema-v2/v3 HTTP responses")

peer_samples=root/"docs/acceptance/gonet-peer-lag/http-samples.json"
if peer_samples.exists():
    values=json.loads(peer_samples.read_text(encoding="utf-8"))
    for sample in values:
        route=route_template(sample["path"])
        validate_response(spec,route,"get",sample["status"],sample["body"],Draft202012Validator,FormatChecker(),"urn:gonet:openapi")
        if route in agent["paths"]:
            validate_response(agent,route,"get",sample["status"],sample["body"],OAS30Validator,oas30_format_checker,"urn:gonet:agent")
    print(f"PASS schema-v4 peer aggregation with {len(values)} real handler responses")

status_samples=root/"docs/acceptance/interface-status-2026-11-06/http-samples.json"
if status_samples.exists():
    values=json.loads(status_samples.read_text(encoding="utf-8"))
    for sample in values:
        route=route_template(sample["path"])
        validate_response(spec,route,"get",sample["status"],sample["body"],Draft202012Validator,FormatChecker(),"urn:gonet:openapi")
        if route in agent["paths"]:
            validate_response(agent,route,"get",sample["status"],sample["body"],OAS30Validator,oas30_format_checker,"urn:gonet:agent")
    print(f"PASS IF-MIB status and peer-lag-v2 with {len(values)} new HTTP responses")

coverage_dir = root / "docs/acceptance/coverage-diagnostics-2026-11-06"
for filename, route in [
    ("live-summary.json", "/api/v1/topology/summary"),
    ("live-device68-neighbors.json", "/api/v1/devices/{device_id}/neighbors"),
    ("live-device68-uplink-path.json", "/api/v1/devices/{device_id}/uplink-path"),
    ("live-device68-collection.json", "/api/v1/topology/collection"),
]:
    path = coverage_dir / filename
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        validate_response(spec, route, "get", 200, payload, Draft202012Validator, FormatChecker(), "urn:gonet:openapi")
        validate_response(agent, route, "get", 200, payload, OAS30Validator, oas30_format_checker, "urn:gonet:agent")
        print(f"PASS both OpenAPI contracts with live {filename}")
all_items = coverage_dir / "live-collection-all.json"
if all_items.exists():
    items = json.loads(all_items.read_text(encoding="utf-8"))
    schema = {"$ref": "#/components/schemas/CollectionItemV2", "components": spec["components"]}
    for item in items:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(item)
    print(f"PASS collection item contract with {len(items)} live diagnostics")
