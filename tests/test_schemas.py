import json
from pathlib import Path


def test_all_agp_schemas_are_valid_json_objects_with_protocol_identity() -> None:
    schemas = sorted(Path("schemas").glob("*.schema.json"))
    assert len(schemas) == 12
    for path in schemas:
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["type"] == "object"
        assert "agp_version" in schema["required"]
        assert schema["properties"]["agp_version"] == {"const": "0.1"}
