"""Validate the supported subset without reconstructing the forwarded request."""

import json
import math

from .models import Finding, ProxyError, Segment

COMMON = {
    "model",
    "stream",
    "temperature",
    "top_p",
    "metadata",
    "store",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "service_tier",
    "user",
}
RESPONSE = COMMON | {
    "input",
    "instructions",
    "max_output_tokens",
    "text",
    "reasoning",
    "truncation",
    "stream_options",
}
CHAT = COMMON | {
    "messages",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "stop",
    "seed",
    "frequency_penalty",
    "presence_penalty",
    "logprobs",
    "top_logprobs",
    "logit_bias",
    "response_format",
    "stream_options",
    "reasoning_effort",
}


def malformed():
    raise ProxyError(400, "invalid_request", "Request does not match a supported JSON structure")


def parse_body(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                malformed()
            result[key] = value
        return result

    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=lambda _: malformed()
        )
    except (ValueError, UnicodeError, RecursionError):
        malformed()
    if not isinstance(data, dict):
        malformed()

    def depth(value, level=0):
        if level > 32:
            malformed()
        if isinstance(value, dict):
            for v in value.values():
                depth(v, level + 1)
        elif isinstance(value, list):
            for v in value:
                depth(v, level + 1)
        elif isinstance(value, float) and not math.isfinite(value):
            malformed()
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError:
                malformed()

    depth(data)
    return data


def extract(data: dict, endpoint: str) -> tuple[list[Segment], list[Finding]]:
    segments, gaps = [], []
    responses = endpoint == "/v1/responses"

    def gap(field):
        gaps.append(
            Finding(
                detector_id="inspection_gap",
                category="unsupported_content",
                severity="high",
                field=field,
                reason="Content or feature is outside the inspectable MVP subset",
            )
        )

    def keys(obj, allowed, field):
        if not isinstance(obj, dict):
            malformed()
        if obj.keys() - allowed:
            # Never echo attacker-controlled key names into errors/logs.
            gap(field)

    def add(value, field, role, source="message"):
        if not isinstance(value, str):
            malformed()
        segments.append(Segment(value, field, role, source))

    def strings(value, field, role="configuration"):
        # Schemas and function arguments are data, not executable detector instructions.
        if isinstance(value, str):
            add(value, field, role, "configuration")
        elif isinstance(value, dict):
            for v in value.values():
                strings(v, field, role)
            for k in value:
                add(k, field, role, "configuration")
        elif isinstance(value, list):
            for v in value:
                strings(v, field, role)

    def content(value, field, role):
        if isinstance(value, str):
            add(value, field, role)
        elif isinstance(value, list):
            texts = []
            for i, part in enumerate(value):
                if not isinstance(part, dict):
                    malformed()
                kind = part.get("type")
                if not isinstance(kind, str):
                    malformed()
                allowed = (
                    {"input_text", "output_text", "refusal"} if responses else {"text", "refusal"}
                )
                if kind not in allowed:
                    gap(f"{field}[{i}]")
                    continue
                key = "refusal" if kind == "refusal" else "text"
                keys(part, {"type", key, "annotations"}, f"{field}[{i}]")
                if not isinstance(part.get(key), str):
                    malformed()
                texts.append(part[key])
                strings(part.get("annotations", []), f"{field}[{i}].annotations", role)
            # Preserve message/role boundaries, combine neighboring parts for split attacks.
            add("".join(texts), field, role)
            if len(texts) > 1:
                add("\n".join(texts), field, role)
        else:
            malformed()

    keys(data, RESPONSE if responses else CHAT, "request")
    if not isinstance(data.get("model"), str) or not data["model"].strip():
        malformed()
    if "stream" in data and type(data["stream"]) is not bool:
        malformed()
    for flag in ("store", "parallel_tool_calls", "logprobs"):
        if flag in data and type(data[flag]) is not bool:
            malformed()
    for number in ("max_tokens", "max_completion_tokens", "max_output_tokens", "n"):
        if number in data and (type(data[number]) is not int or data[number] <= 0):
            malformed()
    for number in ("temperature", "top_p", "frequency_penalty", "presence_penalty"):
        if number in data and type(data[number]) not in (int, float):
            malformed()
    for integer in ("seed", "top_logprobs"):
        if integer in data and type(data[integer]) is not int:
            malformed()
    for string in ("service_tier", "user", "truncation", "reasoning_effort"):
        if string in data and not isinstance(data[string], str):
            malformed()
    for mapping in ("metadata", "logit_bias"):
        if mapping in data:
            if not isinstance(data[mapping], dict):
                malformed()
            for val in data[mapping].values():
                if (mapping == "metadata" and not isinstance(val, str)) or (
                    mapping == "logit_bias" and type(val) not in (int, float)
                ):
                    malformed()
    if "stop" in data and not (
        isinstance(data["stop"], str)
        or (isinstance(data["stop"], list) and all(isinstance(v, str) for v in data["stop"]))
    ):
        malformed()
    if "stream_options" in data:
        options = data["stream_options"]
        keys(
            options,
            {"include_obfuscation"} if responses else {"include_usage", "include_obfuscation"},
            "stream_options",
        )
        for name in ("include_usage", "include_obfuscation"):
            if name in options and type(options[name]) is not bool:
                malformed()
    if "reasoning" in data:
        keys(data["reasoning"], {"effort", "summary"}, "reasoning")
        if any(not isinstance(v, str) for v in data["reasoning"].values()):
            malformed()
    fmt = data.get("response_format")
    if "text" in data:
        keys(data["text"], {"format", "verbosity"}, "text")
        if "verbosity" in data["text"] and not isinstance(data["text"]["verbosity"], str):
            malformed()
        fmt = data["text"].get("format")
    if fmt is not None:
        field = "text.format" if responses else "response_format"
        keys(
            fmt,
            {"type", "name", "schema", "description", "strict"}
            if responses
            else {"type", "json_schema"},
            field,
        )
        if fmt.get("type") not in ("text", "json_object", "json_schema"):
            gap(field)
        if fmt.get("type") == "json_schema":
            schema = fmt if responses else fmt.get("json_schema")
            keys(schema, {"type", "name", "schema", "description", "strict"}, field)
            if not isinstance(schema.get("name"), str) or not isinstance(
                schema.get("schema"), dict
            ):
                malformed()
            if "strict" in schema and type(schema["strict"]) is not bool:
                malformed()
    if "tool_choice" in data:
        choice = data["tool_choice"]
        if isinstance(choice, str):
            if choice not in {"none", "auto", "required"}:
                gap("tool_choice")
        elif isinstance(choice, dict):
            keys(choice, {"type", "name"} if responses else {"type", "function"}, "tool_choice")
            if choice.get("type") != "function":
                gap("tool_choice")
            else:
                fn = choice if responses else choice.get("function")
                keys(fn, {"type", "name"} if responses else {"name"}, "tool_choice")
                if not isinstance(fn.get("name"), str):
                    malformed()
        else:
            malformed()
    if "instructions" in data and data["instructions"] is not None:
        add(data["instructions"], "instructions", "developer", "instructions")
    value = data.get("input" if responses else "messages")
    if responses and isinstance(value, str):
        add(value, "input", "user")
    else:
        if not isinstance(value, list) or not value:
            malformed()
        root = "input" if responses else "messages"
        for i, item in enumerate(value):
            field = f"{root}[{i}]"
            if not isinstance(item, dict):
                malformed()
            kind = item.get("type", "message")
            if not isinstance(kind, str):
                malformed()
            if responses and kind == "function_call_output":
                keys(item, {"type", "call_id", "output", "id", "status"}, field)
                if not isinstance(item.get("call_id"), str):
                    malformed()
                content(item.get("output"), field + ".output", "tool")
                continue
            if responses and kind == "function_call":
                keys(item, {"type", "call_id", "name", "arguments", "id", "status"}, field)
                for key in ("call_id", "name", "arguments"):
                    add(item.get(key), field + "." + key, "assistant", "function_call")
                continue
            if kind != "message":
                gap(field)
                continue
            keys(
                item,
                {"role", "content", "name", "tool_calls", "tool_call_id", "refusal"}
                | ({"type", "id", "status"} if responses else set()),
                field,
            )
            role = item.get("role")
            roles = {"user", "assistant", "system", "developer"} | (
                set() if responses else {"tool"}
            )
            if not isinstance(role, str) or role not in roles:
                malformed()
            if role == "tool" and not isinstance(item.get("tool_call_id"), str):
                malformed()
            if item.get("content") is not None:
                content(item["content"], field + ".content", role)
            elif role != "assistant" or not (item.get("tool_calls") or item.get("refusal")):
                malformed()
            for key in ("name", "refusal"):
                if item.get(key) is not None:
                    add(item[key], field + "." + key, role)
            if "tool_calls" in item:
                if role != "assistant" or not isinstance(item["tool_calls"], list):
                    malformed()
                for j, call in enumerate(item["tool_calls"]):
                    path = f"{field}.tool_calls[{j}]"
                    keys(call, {"id", "type", "function"}, path)
                    if call.get("type") != "function":
                        gap(path)
                        continue
                    if not isinstance(call.get("id"), str):
                        malformed()
                    function = call.get("function")
                    keys(function, {"name", "arguments"}, path)
                    for k in ("name", "arguments"):
                        add(function.get(k), path + ".function." + k, role, "function_call")
    if "tools" in data:
        if not isinstance(data["tools"], list):
            malformed()
        for i, tool in enumerate(data["tools"]):
            field = f"tools[{i}]"
            if not isinstance(tool, dict):
                malformed()
            if tool.get("type") != "function":
                gap(field)
                continue
            fn = tool if responses else tool.get("function")
            keys(
                tool,
                {"type", "name", "description", "parameters", "strict"}
                if responses
                else {"type", "function"},
                field,
            )
            keys(fn, {"type", "name", "description", "parameters", "strict"}, field)
            if not isinstance(fn.get("name"), str):
                malformed()
            if "parameters" in fn and not isinstance(fn["parameters"], dict):
                malformed()
            if "description" in fn and not isinstance(fn["description"], str):
                malformed()
            if "strict" in fn and type(fn["strict"]) is not bool:
                malformed()
            strings(tool, field)
    # All remaining supported strings are inspected, including schemas and configuration.
    for key in sorted(
        data.keys()
        & (RESPONSE if responses else CHAT) - {"input", "messages", "instructions", "tools"}
    ):
        strings(data[key], key)
    return segments, gaps
