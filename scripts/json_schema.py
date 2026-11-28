#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Small JSON Schema validator for the schemas shipped in this repository.

The validator implements the draft-07 and draft 2020-12 validation and
applicator keywords used by those schemas.  It is intentionally generic: it
knows nothing about inventories, diffs, profiles or CycloneDX.  Unknown
annotation keywords are ignored, as JSON Schema requires.  Local and
relative-file references are resolved offline; network references are never
fetched.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse


class SchemaError(ValueError):
    """The schema or one of its references is malformed or unavailable."""


def _type_name(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return type(value).__name__


def _json_type(instance, wanted: str) -> bool:
    if wanted == "null":
        return instance is None
    if wanted == "boolean":
        return isinstance(instance, bool)
    if wanted == "object":
        return isinstance(instance, dict)
    if wanted == "array":
        return isinstance(instance, list)
    if wanted == "string":
        return isinstance(instance, str)
    if wanted == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if wanted == "number":
        return (isinstance(instance, int | float)
                and not isinstance(instance, bool))
    return False


def _canonical(instance):
    if isinstance(instance, dict):
        return ("object", tuple((key, _canonical(instance[key])) for key in sorted(instance)))
    if isinstance(instance, list):
        return ("array", tuple(_canonical(item) for item in instance))
    return (type(instance).__name__, instance)


def _pointer(document, fragment: str):
    if fragment in ("", "/"):
        return document
    if not fragment.startswith("/"):
        raise SchemaError(f"unsupported non-JSON-pointer reference #{fragment}")
    current = document
    for raw in fragment[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise SchemaError(f"reference token {token!r} is absent")
            current = current[token]
        elif isinstance(current, list):
            try:
                index = int(token)
            except ValueError as exc:
                raise SchemaError(f"array reference token {token!r} is not numeric") from exc
            if index < 0 or index >= len(current):
                raise SchemaError(f"array reference index {index} is out of range")
            current = current[index]
        else:
            raise SchemaError(f"reference token {token!r} crosses a scalar")
    return current


class Store:
    """Offline schema-document store keyed by canonical file URI and $id."""

    def __init__(self):
        self.documents = {}
        self.by_path = {}

    @staticmethod
    def _file_key(path: Path) -> str:
        return path.resolve().as_uri()

    def add(self, path: Path, document) -> None:
        resolved = path.resolve()
        key = self._file_key(resolved)
        self.documents[key] = (document, resolved)
        self.by_path[resolved] = key
        if isinstance(document, dict) and isinstance(document.get("$id"), str):
            self.documents[document["$id"]] = (document, resolved)

    def load(self, path: Path):
        resolved = path.resolve()
        key = self.by_path.get(resolved)
        if key is not None:
            return self.documents[key]
        try:
            document = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SchemaError(f"cannot load schema {resolved}: {exc}") from exc
        self.add(resolved, document)
        return self.documents[self._file_key(resolved)]

    def resolve(self, reference: str, base: Path, base_key: str):
        url, fragment = urldefrag(reference)
        if not url:
            key = base_key
        else:
            base_uri = self._file_key(base)
            absolute = urljoin(base_uri, url)
            if absolute in self.documents:
                key = absolute
            else:
                parsed = urlparse(absolute)
                if parsed.scheme and parsed.scheme != "file":
                    raise SchemaError(f"network schema reference is not offline-resolvable: {reference}")
                path = Path(parsed.path)
                key = self._file_key(path)
                if key not in self.documents:
                    self.load(path)
        if key not in self.documents:
            raise SchemaError(f"schema reference is not loaded: {reference}")
        document, path = self.documents[key]
        try:
            target = _pointer(document, fragment)
        except SchemaError as exc:
            raise SchemaError(f"{reference}: {exc}") from exc
        return target, path, key


class Validator:
    def __init__(self, schema, schema_path: Path, strict: bool = False):
        self.store = Store()
        self.schema_path = schema_path.resolve()
        # Strict mode fails closed: an object whose schema enumerates
        # known fields (properties/patternProperties) but sets no explicit
        # additionalProperties allows no undeclared properties. Explicit
        # additionalProperties and bare combinator/required-only nodes are
        # respected as written in both modes.
        self.strict = strict
        self.store.add(self.schema_path, schema)
        self.root_key = self.store._file_key(self.schema_path)

    def add_resource(self, path: Path, document=None) -> None:
        if document is None:
            self.store.load(path)
        else:
            self.store.add(path, document)

    def validate(self, instance) -> list[str]:
        schema = self.store.documents[self.root_key][0]
        return list(self._validate(instance, schema, self.schema_path, self.root_key, "$", frozenset()))

    def _error(self, path: str, message: str):
        yield f"{path}: {message}"

    def _validate(self, instance, schema, base: Path, base_key: str, path: str, active):
        if isinstance(schema, bool):
            if schema:
                return
            yield from self._error(path, "boolean schema is false")
            return
        if not isinstance(schema, dict):
            raise SchemaError(f"schema at {base} is not an object or boolean")
        for keyword in ("$dynamicRef", "$recursiveRef", "dependentSchemas",
                        "unevaluatedProperties", "unevaluatedItems",
                        "contentSchema"):
            if keyword in schema:
                raise SchemaError(f"unsupported keyword {keyword!r} at {path}")

        ref = schema.get("$ref")
        if isinstance(ref, str):
            identity = (id(schema), id(instance), ref)
            if identity in active:
                return
            target, target_base, target_key = self.store.resolve(ref, base, base_key)
            yield from self._validate(
                instance, target, target_base, target_key, path, active | {identity}
            )
            # In draft-07 $ref replaces siblings.  The shipped 2020-12
            # schemas do not rely on sibling evaluation beside $ref.
            return

        expected_type = schema.get("type")
        if expected_type is not None:
            types = expected_type if isinstance(expected_type, list) else [expected_type]
            if not any(isinstance(one, str) and _json_type(instance, one) for one in types):
                wanted = " or ".join(str(one) for one in types)
                yield from self._error(path, f"is {_type_name(instance)}, expected {wanted}")
                return

        if "enum" in schema:
            values = schema["enum"]
            if not isinstance(values, list):
                raise SchemaError("enum is not an array")
            if not any(instance == value and type(instance) is type(value) for value in values):
                yield from self._error(path, f"value {instance!r} is not in the enum")
        if "const" in schema:
            value = schema["const"]
            if instance != value or type(instance) is not type(value):
                yield from self._error(path, f"value {instance!r} is not const {value!r}")

        if isinstance(instance, dict):
            yield from self._object_keywords(instance, schema, base, base_key, path, active)
        if isinstance(instance, list):
            yield from self._array_keywords(instance, schema, base, base_key, path, active)
        if isinstance(instance, str):
            yield from self._string_keywords(instance, schema, path)
        if isinstance(instance, int | float) and not isinstance(instance, bool):
            yield from self._number_keywords(instance, schema, path)

        yield from self._applicator_keywords(instance, schema, base, base_key, path, active)

    def _subschema(self, value, instance, subschema, base, base_key, path, active, label):
        yield from self._validate(instance, subschema, base, base_key, path, active)

    def _object_keywords(self, instance, schema, base, base_key, path, active):
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if isinstance(key, str) and key not in instance:
                    yield from self._error(path, f"required property {key!r} is missing")
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, subschema in properties.items():
                if key in instance:
                    yield from self._validate(
                        instance[key], subschema, base, base_key,
                        f"{path}.{key}", active,
                    )
        patterns = schema.get("patternProperties", {})
        matched = set()
        if isinstance(patterns, dict):
            for pattern, subschema in patterns.items():
                try:
                    regex = re.compile(pattern)
                except re.error as exc:
                    raise SchemaError(f"invalid patternProperties regex {pattern!r}: {exc}") from exc
                for key, value in instance.items():
                    if regex.search(key):
                        matched.add(key)
                        yield from self._validate(
                            value, subschema, base, base_key, f"{path}.{key}", active
                        )
        # Strict closes the world only where the schema enumerates known
        # fields (properties/patternProperties). Bare combinators (anyOf and
        # friends), required-only and propertyNames-only nodes keep the default
        # open world so shape stays delegated to their own keywords.
        declares = "properties" in schema or "patternProperties" in schema
        additional = schema.get(
            "additionalProperties", False if (self.strict and declares) else True
        )
        defined = set(properties) if isinstance(properties, dict) else set()
        for key, value in instance.items():
            if key in defined or key in matched:
                continue
            if additional is False:
                yield from self._error(path, f"additional property {key!r} is not allowed")
            elif isinstance(additional, (dict, bool)) and additional is not True:
                yield from self._validate(
                    value, additional, base, base_key, f"{path}.{key}", active
                )
        min_properties = schema.get("minProperties")
        if isinstance(min_properties, int) and len(instance) < min_properties:
            yield from self._error(path, f"has {len(instance)} properties, fewer than {min_properties}")
        max_properties = schema.get("maxProperties")
        if isinstance(max_properties, int) and len(instance) > max_properties:
            yield from self._error(path, f"has {len(instance)} properties, more than {max_properties}")
        property_names = schema.get("propertyNames")
        if isinstance(property_names, (dict, bool)):
            for key in instance:
                yield from self._validate(key, property_names, base, base_key, f"{path}.{key}", active)
        dependent = schema.get("dependentRequired", {})
        if isinstance(dependent, dict):
            for key, names in dependent.items():
                if key in instance and isinstance(names, list):
                    for name in names:
                        if isinstance(name, str) and name not in instance:
                            yield from self._error(path, f"property {key!r} depends on missing {name!r}")
        legacy_dependent = schema.get("dependencies", {})
        if isinstance(legacy_dependent, dict):
            for key, dependency in legacy_dependent.items():
                if key not in instance:
                    continue
                if isinstance(dependency, list):
                    for name in dependency:
                        if isinstance(name, str) and name not in instance:
                            yield from self._error(path, f"property {key!r} depends on missing {name!r}")
                elif isinstance(dependency, (dict, bool)):
                    yield from self._validate(instance, dependency, base, base_key, path, active)

    def _array_keywords(self, instance, schema, base, base_key, path, active):
        items = schema.get("items")
        tuple_schemas = schema.get("prefixItems")
        if tuple_schemas is None and isinstance(items, list):
            tuple_schemas = items
            items = None
        if isinstance(tuple_schemas, list):
            for index, subschema in enumerate(tuple_schemas):
                if index < len(instance):
                    yield from self._validate(
                        instance[index], subschema, base, base_key, f"{path}[{index}]", active
                    )
            rest = schema.get("additionalItems", schema.get("items", True))
            if len(instance) > len(tuple_schemas):
                if rest is False:
                    yield from self._error(path, f"has more than the {len(tuple_schemas)} tuple items")
                elif isinstance(rest, (dict, bool)) and rest is not True:
                    for index in range(len(tuple_schemas), len(instance)):
                        yield from self._validate(
                            instance[index], rest, base, base_key, f"{path}[{index}]", active
                        )
        elif isinstance(items, (dict, bool)):
            for index, value in enumerate(instance):
                yield from self._validate(value, items, base, base_key, f"{path}[{index}]", active)
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(instance) < min_items:
            yield from self._error(path, f"has {len(instance)} items, fewer than {min_items}")
        max_items = schema.get("maxItems")
        if isinstance(max_items, int) and len(instance) > max_items:
            yield from self._error(path, f"has {len(instance)} items, more than {max_items}")
        if schema.get("uniqueItems") is True:
            seen = set()
            for index, value in enumerate(instance):
                marker = _canonical(value)
                if marker in seen:
                    yield from self._error(path, f"item {index} duplicates an earlier item")
                    break
                seen.add(marker)
        contains = schema.get("contains")
        if isinstance(contains, (dict, bool)):
            found = False
            for index, value in enumerate(instance):
                if not list(self._validate(value, contains, base, base_key, f"{path}[{index}]", active)):
                    found = True
                    break
            if not found:
                yield from self._error(path, "no item matches contains")

    def _string_keywords(self, instance, schema, path):
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(instance) < min_length:
            yield from self._error(path, f"length {len(instance)} is below {min_length}")
        max_length = schema.get("maxLength")
        if isinstance(max_length, int) and len(instance) > max_length:
            yield from self._error(path, f"length {len(instance)} exceeds {max_length}")
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            try:
                regex = re.compile(pattern)
            except re.error as exc:
                raise SchemaError(f"invalid pattern {pattern!r}: {exc}") from exc
            if not regex.search(instance):
                yield from self._error(path, f"does not match pattern {pattern!r}")
        format_name = schema.get("format")
        if isinstance(format_name, str) and not self._format_valid(instance, format_name):
            yield from self._error(path, f"is not a valid {format_name}")

    @staticmethod
    def _format_valid(instance: str, name: str) -> bool:
        # Unknown formats are annotations.  These common formats are the
        # only ones needed by the shipped schemas; keep checks conservative.
        try:
            if name == "date-time":
                datetime.fromisoformat(instance.replace("Z", "+00:00"))
                return "T" in instance
            if name == "email":
                return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", instance))
            if name in ("uri", "iri"):
                return bool(urlparse(instance).scheme)
            if name in ("uri-reference", "iri-reference"):
                return True
            if name == "ipv4":
                ipaddress.IPv4Address(instance)
                return True
            if name == "ipv6":
                ipaddress.IPv6Address(instance)
                return True
            if name == "hostname":
                return bool(instance) and len(instance) <= 253 and all(
                    part and len(part) <= 63 and re.fullmatch(r"[A-Za-z0-9-]+", part)
                    and not part.startswith("-") and not part.endswith("-")
                    for part in instance.rstrip(".").split(".")
                )
            if name == "regex":
                re.compile(instance)
                return True
        except (ValueError, re.error):
            return False
        return True

    def _number_keywords(self, instance, schema, path):
        minimum = schema.get("minimum")
        if isinstance(minimum, int | float) and instance < minimum:
            yield from self._error(path, f"is below minimum {minimum}")
        maximum = schema.get("maximum")
        if isinstance(maximum, int | float) and instance > maximum:
            yield from self._error(path, f"exceeds maximum {maximum}")
        exclusive_minimum = schema.get("exclusiveMinimum")
        if isinstance(exclusive_minimum, int | float) and not isinstance(exclusive_minimum, bool):
            if instance <= exclusive_minimum:
                yield from self._error(path, f"does not exceed exclusiveMinimum {exclusive_minimum}")
        elif exclusive_minimum is True and isinstance(minimum, int | float) and instance <= minimum:
            yield from self._error(path, f"does not exceed minimum {minimum}")
        exclusive_maximum = schema.get("exclusiveMaximum")
        if isinstance(exclusive_maximum, int | float) and not isinstance(exclusive_maximum, bool):
            if instance >= exclusive_maximum:
                yield from self._error(path, f"is not below exclusiveMaximum {exclusive_maximum}")
        elif exclusive_maximum is False:
            pass
        elif exclusive_maximum is True and isinstance(maximum, int | float) and instance >= maximum:
            yield from self._error(path, f"is not below maximum {maximum}")
        multiple = schema.get("multipleOf")
        if isinstance(multiple, int | float) and multiple:
            quotient = instance / multiple
            if abs(quotient - round(quotient)) > 1e-12:
                yield from self._error(path, f"is not a multiple of {multiple}")

    def _applicator_keywords(self, instance, schema, base, base_key, path, active):
        for key in ("allOf",):
            clauses = schema.get(key)
            if isinstance(clauses, list):
                for subschema in clauses:
                    yield from self._validate(instance, subschema, base, base_key, path, active)
        clauses = schema.get("anyOf")
        if isinstance(clauses, list):
            matches = [
                not list(self._validate(instance, subschema, base, base_key, path, active))
                for subschema in clauses
            ]
            if not any(matches):
                yield from self._error(path, "matches no anyOf clause")
        clauses = schema.get("oneOf")
        if isinstance(clauses, list):
            matches = [
                not list(self._validate(instance, subschema, base, base_key, path, active))
                for subschema in clauses
            ]
            if sum(1 for matched in matches if matched) != 1:
                yield from self._error(path, f"matches {sum(matches)} oneOf clauses, expected exactly one")
        negation = schema.get("not")
        if isinstance(negation, (dict, bool)):
            if not list(self._validate(instance, negation, base, base_key, path, active)):
                yield from self._error(path, "matches the forbidden not schema")
        condition = schema.get("if")
        if isinstance(condition, (dict, bool)):
            condition_ok = not list(self._validate(instance, condition, base, base_key, path, active))
            branch_key = "then" if condition_ok else "else"
            branch = schema.get(branch_key)
            if isinstance(branch, (dict, bool)):
                yield from self._validate(instance, branch, base, base_key, path, active)


def validate(instance, schema, schema_path: Path, resources=(), strict: bool = False) -> list[str]:
    """Validate *instance* and return deterministic human-readable errors."""
    validator = Validator(schema, schema_path, strict=strict)
    for resource in resources:
        validator.add_resource(Path(resource))
    return validator.validate(instance)


def load_schema(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaError(f"cannot load schema {path}: {exc}") from exc


def validate_file(instance_path: Path, schema_path: Path, resources=(), strict: bool = False) -> list[str]:
    try:
        instance = json.loads(instance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"$: cannot parse instance JSON: {exc}"]
    try:
        schema = load_schema(schema_path)
    except SchemaError as exc:
        return [f"$: {exc}"]
    try:
        return validate(instance, schema, schema_path, resources, strict)
    except SchemaError as exc:
        return [f"$: schema error: {exc}"]


def main(argv=None) -> int:
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        print("usage: json_schema.py INSTANCE.json SCHEMA.json [RESOURCE.schema.json ...]", file=sys.stderr)
        return 2
    errors = validate_file(Path(args[0]), Path(args[1]), [Path(row) for row in args[2:]])
    if errors:
        for error in errors[:20]:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
