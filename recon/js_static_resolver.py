"""Bounded, non-executing JavaScript template and constant-map resolution.

This module deliberately implements only a small static subset.  Downloaded
JavaScript is parsed as data and is never evaluated.  Unknown expressions stay
unknown rather than being guessed or executed.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import time
from typing import Any, Iterator, Optional


MAX_SOURCE_BYTES = 8 * 1024 * 1024
# Large production bundles routinely exceed 300k concrete-syntax nodes.  The
# source-byte cap remains the primary parser bound; this traversal cap prevents
# pathological trees from being retained indefinitely.
MAX_AST_NODES = 1_000_000
MAX_SCOPES = 4_000
MAX_RESULTS = 4_000
MAX_VALUE_LENGTH = 2_000
MAX_RESOLUTION_DEPTH = 12
MAX_FIXPOINT_PASSES = 5
MAX_RESOLUTION_SECONDS = 3.0

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
FUNCTION_NODES = {
    "arrow_function", "function", "function_declaration", "function_expression",
    "generator_function", "generator_function_declaration", "method_definition",
}
SENSITIVE_NAME_RE = re.compile(
    r"(?:authorization|cookie|csrf|xsrf|token|password|passwd|secret|assertion|"
    r"saml|nonce|session|credential|private.?key)",
    re.IGNORECASE,
)
ENDPOINT_HINT_RE = re.compile(
    r"(?:^|/)(?:api|rest|graphql|service|services|odata|v\d+)(?:/|$)|"
    r"(?:get|list|search|find|create|add|update|edit|delete|remove|export|import|"
    r"report|user|account|admin|questionnaire|migrate|quaterly|quarterly|master)",
    re.IGNORECASE,
)
STATIC_SUFFIX_RE = re.compile(
    r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|html)(?:$|[?#])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ResolvedString:
    value: str
    resolution: str
    unresolved: tuple[str, ...] = ()
    evidence: str = ""


@dataclass(frozen=True)
class StaticEndpoint:
    value: str
    method: Optional[str]
    resolution: str
    method_source: str
    unresolved: tuple[str, ...]
    evidence: str


ResolvedValue = ResolvedString | dict[str, "ResolvedValue"]


def _load_parser():
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_javascript

        return Parser(Language(tree_sitter_javascript.language()))
    except Exception:
        return None


def _walk(root, *, skip_nested_functions: bool = False) -> Iterator[Any]:
    stack = [root]
    visited = 0
    while stack and visited < MAX_AST_NODES:
        node = stack.pop()
        visited += 1
        yield node
        if skip_nested_functions and node is not root and node.type in FUNCTION_NODES:
            continue
        stack.extend(reversed(node.children))


def _text(node, source: bytes, limit: int = MAX_VALUE_LENGTH) -> str:
    if node is None:
        return ""
    return source[node.start_byte:min(node.end_byte, node.start_byte + limit)].decode("utf-8", errors="replace")


def _property_name(node, source: bytes) -> str:
    if node is None:
        return ""
    raw = _text(node, source).strip()
    if node.type in {"string", "string_fragment"} and len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
        return _decode_string(raw)
    return raw


def _decode_string(raw: str) -> str:
    value = raw.strip()
    if len(value) < 2 or value[0] not in "\"'" or value[-1] != value[0]:
        return value
    quote = value[0]
    body = value[1:-1]
    try:
        if quote == '"':
            return json.loads(value)
        return json.loads('"' + body.replace('"', '\\"').replace("\\'", "'") + '"')
    except Exception:
        return body.replace("\\/", "/")


def _merge_resolution(parts: list[ResolvedString], fallback: str) -> tuple[str, tuple[str, ...]]:
    unresolved: list[str] = []
    modes = set()
    for part in parts:
        modes.add(part.resolution)
        for item in part.unresolved:
            if item not in unresolved:
                unresolved.append(item)
    if unresolved:
        return "template_partial", tuple(unresolved)
    if "template_resolved" in modes or len(parts) > 1:
        return "template_resolved", ()
    return fallback, ()


def _safe_join(parts: list[ResolvedString], evidence: str) -> Optional[ResolvedString]:
    value = "".join(part.value for part in parts)
    if not value or len(value) > MAX_VALUE_LENGTH:
        return None
    resolution, unresolved = _merge_resolution(parts, "literal")
    return ResolvedString(value, resolution, unresolved, evidence[:500])


def _unique_string(values: list[ResolvedString]) -> Optional[ResolvedString]:
    distinct: dict[str, ResolvedString] = {item.value: item for item in values if item.value}
    return next(iter(distinct.values())) if len(distinct) == 1 else None


def _member_property(node, source: bytes) -> str:
    if node is None or node.type not in {"member_expression", "subscript_expression"}:
        return ""
    prop = node.child_by_field_name("property") or node.child_by_field_name("index")
    return _property_name(prop, source)


def _evaluate(
    node,
    source: bytes,
    env: dict[str, ResolvedValue],
    property_literals: dict[str, list[ResolvedString]],
    *,
    depth: int = 0,
) -> Optional[ResolvedValue]:
    if node is None or depth > MAX_RESOLUTION_DEPTH:
        return None
    node_type = node.type
    evidence = _text(node, source, 500)

    if node_type == "string":
        value = _decode_string(_text(node, source))
        if not value or len(value) > MAX_VALUE_LENGTH:
            return None
        return ResolvedString(value, "literal", (), evidence)
    if node_type == "identifier":
        return env.get(_text(node, source))
    if node_type in {"parenthesized_expression", "await_expression"}:
        named = node.named_children
        return _evaluate(named[0], source, env, property_literals, depth=depth + 1) if named else None
    if node_type == "template_string":
        parts: list[ResolvedString] = []
        for child in node.children:
            if child.type == "string_fragment":
                fragment = _text(child, source)
                if fragment:
                    parts.append(ResolvedString(fragment, "literal", (), fragment[:500]))
            elif child.type == "escape_sequence":
                parts.append(ResolvedString(_decode_string('"' + _text(child, source) + '"'), "literal"))
            elif child.type == "template_substitution":
                expression = child.named_children[0] if child.named_children else None
                resolved = _evaluate(expression, source, env, property_literals, depth=depth + 1)
                if isinstance(resolved, ResolvedString):
                    parts.append(ResolvedString(resolved.value, "template_resolved", resolved.unresolved, resolved.evidence))
                else:
                    expression_text = _text(expression, source, 120) or "expression"
                    placeholder = "" if not parts else "{param}"
                    parts.append(ResolvedString(placeholder, "template_partial", (expression_text,), expression_text))
        return _safe_join(parts, evidence)
    if node_type == "binary_expression":
        operator = next((child for child in node.children if child.type == "+"), None)
        if operator is None:
            return None
        left = _evaluate(node.child_by_field_name("left"), source, env, property_literals, depth=depth + 1)
        right = _evaluate(node.child_by_field_name("right"), source, env, property_literals, depth=depth + 1)
        if isinstance(left, ResolvedString) and isinstance(right, ResolvedString):
            return _safe_join([left, right], evidence)
        return None
    if node_type == "object":
        result: dict[str, ResolvedValue] = {}
        for child in node.named_children:
            if child.type not in {"pair", "pair_pattern"}:
                continue
            key = _property_name(child.child_by_field_name("key"), source)
            if not key or SENSITIVE_NAME_RE.search(key):
                continue
            value = _evaluate(child.child_by_field_name("value"), source, env, property_literals, depth=depth + 1)
            if value is not None:
                result[key] = value
        return result or None
    if node_type in {"member_expression", "subscript_expression"}:
        obj = _evaluate(node.child_by_field_name("object"), source, env, property_literals, depth=depth + 1)
        prop = _member_property(node, source)
        if isinstance(obj, dict) and prop in obj:
            return obj[prop]
        if prop and not SENSITIVE_NAME_RE.search(prop):
            return _unique_string(property_literals.get(prop, []))
        return None
    return None


def _looks_like_endpoint(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw or len(raw) > MAX_VALUE_LENGTH or STATIC_SUFFIX_RE.search(raw):
        return False
    if raw.startswith(("data:", "blob:", "javascript:", "mailto:", "#")):
        return False
    path = raw.split("?", 1)[0]
    return "/" in path and bool(ENDPOINT_HINT_RE.search(path))


def _flatten(value: ResolvedValue, prefix: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], ResolvedString]]:
    if isinstance(value, ResolvedString):
        yield prefix, value
        return
    for key, child in value.items():
        yield from _flatten(child, prefix + (key,))


def resolve_static_endpoints(text: str) -> list[StaticEndpoint]:
    """Return statically reconstructed endpoint facts without executing code."""
    deadline = time.monotonic() + MAX_RESOLUTION_SECONDS
    source = text.encode("utf-8", errors="replace")
    if not source or len(source) > MAX_SOURCE_BYTES:
        return []
    parser = _load_parser()
    if parser is None:
        return []
    try:
        root = parser.parse(source).root_node
    except Exception:
        return []
    if time.monotonic() > deadline:
        return []

    all_nodes = list(_walk(root))
    if len(all_nodes) >= MAX_AST_NODES or time.monotonic() > deadline:
        return []

    property_literals: dict[str, list[ResolvedString]] = {}
    for node in all_nodes:
        if time.monotonic() > deadline:
            return []
        if node.type not in {"pair", "pair_pattern"}:
            continue
        key = _property_name(node.child_by_field_name("key"), source)
        if not key or SENSITIVE_NAME_RE.search(key):
            continue
        value_node = node.child_by_field_name("value")
        if value_node is not None and value_node.type == "string":
            value = _decode_string(_text(value_node, source))
            if value and len(value) <= MAX_VALUE_LENGTH:
                property_literals.setdefault(key, []).append(
                    ResolvedString(value, "literal", (), _text(node, source, 500))
                )

    scopes = [root]
    scopes.extend(node for node in all_nodes if node.type in FUNCTION_NODES)
    scopes = scopes[:MAX_SCOPES]
    scoped_envs: list[tuple[Any, dict[str, ResolvedValue]]] = []
    property_endpoints: dict[str, list[ResolvedString]] = {}
    facts: list[StaticEndpoint] = []
    seen_facts: set[tuple[Optional[str], str, str]] = set()

    def add_fact(value: ResolvedString, method: Optional[str], method_source: str) -> None:
        if len(facts) >= MAX_RESULTS or not _looks_like_endpoint(value.value):
            return
        key = (method, value.value, value.resolution)
        if key in seen_facts:
            return
        seen_facts.add(key)
        facts.append(StaticEndpoint(
            value=value.value,
            method=method,
            resolution=value.resolution,
            method_source=method_source,
            unresolved=value.unresolved,
            evidence=value.evidence[:500],
        ))

    for scope in scopes:
        if time.monotonic() > deadline:
            return []
        env: dict[str, ResolvedValue] = {}
        declarators = [node for node in _walk(scope, skip_nested_functions=True) if node.type == "variable_declarator"]
        for _pass in range(MAX_FIXPOINT_PASSES):
            if time.monotonic() > deadline:
                return []
            changed = False
            for declaration in declarators:
                name_node = declaration.child_by_field_name("name")
                value_node = declaration.child_by_field_name("value")
                if name_node is None or name_node.type != "identifier" or value_node is None:
                    continue
                name = _text(name_node, source)
                if not name or SENSITIVE_NAME_RE.search(name):
                    continue
                value = _evaluate(value_node, source, env, property_literals)
                if value is not None and env.get(name) != value:
                    env[name] = value
                    changed = True
            if not changed:
                break
        scoped_envs.append((scope, env))
        for value in env.values():
            for property_path, leaf in _flatten(value):
                if property_path:
                    property_endpoints.setdefault(property_path[-1], []).append(leaf)
                add_fact(leaf, None, "constant_map")

    unique_endpoint_properties = {
        key: value for key, values in property_endpoints.items()
        if (value := _unique_string([item for item in values if _looks_like_endpoint(item.value)])) is not None
    }

    for node in all_nodes:
        if time.monotonic() > deadline:
            return []
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        method_name = _member_property(function, source).lower()
        if method_name not in HTTP_METHODS:
            continue
        arguments = node.child_by_field_name("arguments")
        first_arg = arguments.named_children[0] if arguments is not None and arguments.named_children else None
        if first_arg is None:
            continue
        resolved: Optional[ResolvedString] = None
        property_name = _member_property(first_arg, source)
        if property_name:
            resolved = unique_endpoint_properties.get(property_name)
        if resolved is None:
            containing = [
                (scope.end_byte - scope.start_byte, env)
                for scope, env in scoped_envs
                if scope.start_byte <= node.start_byte and scope.end_byte >= node.end_byte
            ]
            if containing:
                env = min(containing, key=lambda item: item[0])[1]
                candidate = _evaluate(first_arg, source, env, property_literals)
                resolved = candidate if isinstance(candidate, ResolvedString) else None
        if resolved is not None:
            add_fact(
                ResolvedString(resolved.value, resolved.resolution, resolved.unresolved, _text(node, source, 500)),
                method_name.upper(),
                "request_call",
            )

    values_with_methods = {fact.value for fact in facts if fact.method}
    return [fact for fact in facts if fact.method or fact.value not in values_with_methods]
