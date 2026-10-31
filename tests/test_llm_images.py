"""Multimodal transport tests for the revio ``agent/llm.py`` seam, using a fake SDK only."""

import base64
import json
from pathlib import Path

import httpx
import pytest
from openai import BadRequestError, RateLimitError

from pulseguard.agents.llm import (
    MAX_IMAGE_BYTES,
    ImageInputError,
    VisionUnsupportedError,
    image_content_parts,
    output_schema,
)
from tests.test_llm import client, completion

PNG = b"\x89PNG\r\n\x1a\n"
JPEG = b"\xff\xd8\xff\xe0"


@pytest.mark.parametrize(("suffix", "data", "mime"), [
    (".PNG", PNG, "image/png"), (".jpg", JPEG, "image/jpeg"),
    (".jpeg", JPEG, "image/jpeg"),
])
def test_image_parts_reach_fake_sdk(tmp_path: Path, suffix: str, data: bytes, mime: str):
    path = tmp_path / f"architecture{suffix}"
    path.write_bytes(data)
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200, json=completion())

    adapter = client(handler)
    adapter.chat("system", "extract", schema=output_schema("verdict"), images=[path])
    parts = calls[0]["messages"][1]["content"]
    assert calls[0]["messages"][0] == {"role": "system", "content": "system"}
    assert parts[0]["type"] == "text" and parts[0]["text"].startswith("extract\n")
    assert "Return JSON matching:" in parts[0]["text"]
    assert parts[1] == {"type": "image_url", "image_url": {
        "url": f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}",
    }}
    assert len(parts) == 2


@pytest.mark.parametrize("images", [None, []])
def test_no_images_keeps_original_text_request(images):
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200, json=completion())

    client(handler).chat("s", "u", schema=output_schema("verdict"), images=images)
    assert isinstance(calls[0]["messages"][1]["content"], str)


@pytest.mark.parametrize(("suffix", "data", "reason"), [
    (".gif", b"GIF89a", "Only PNG and JPEG"),
    (".png", JPEG, "does not match"), (".jpg", PNG, "does not match"),
    (".png", b"", "does not match"),
    (".png", PNG + b"x" * (MAX_IMAGE_BYTES + 1), "exceeds 4 MiB"),
])
def test_bad_images_never_call_provider(tmp_path, suffix, data, reason):
    path = tmp_path / f"image{suffix}"
    path.write_bytes(data)

    def handler(request):
        raise AssertionError("invalid image reached provider")

    with pytest.raises(ImageInputError, match=reason):
        client(handler).chat("s", "u", schema={}, images=[path])


def test_image_limit_includes_all_images_and_accepts_exact_boundary(tmp_path):
    first = tmp_path / "first.png"
    second = tmp_path / "second.jpg"
    first.write_bytes(PNG + b"x" * (MAX_IMAGE_BYTES - len(PNG) - len(JPEG)))
    second.write_bytes(JPEG)
    parts = image_content_parts([first, second])
    assert len(parts) == 2
    assert parts[1]["image_url"]["url"].startswith("data:image/jpeg;base64,")
    second.write_bytes(JPEG + b"x")
    with pytest.raises(ImageInputError, match="exceeds 4 MiB"):
        image_content_parts([first, second])


@pytest.mark.parametrize("status", [400, 404, 422])
@pytest.mark.parametrize("message", [
    "image_url is unsupported", "Vision unavailable", "Invalid content type",
    "Unsupported content_type", "content-type not supported",
])
def test_vision_capability_errors_are_typed_without_retry(tmp_path, status, message):
    path = tmp_path / "image.png"
    path.write_bytes(PNG)
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        return httpx.Response(status, json={"error": {"message": message + " secret-value"}})

    adapter = client(handler)
    with pytest.raises(VisionUnsupportedError) as exc:
        adapter.chat("s", "u", schema={}, images=[path])
    assert exc.value.status_code == status
    assert "secret-value" not in str(exc.value)
    assert len(calls) == 1
    assert adapter._schema_supported is True


@pytest.mark.parametrize("message", ["response_format unsupported", "rate limited"])
def test_images_survive_existing_schema_and_transient_retries(tmp_path, monkeypatch, message):
    monkeypatch.setattr("pulseguard.agents.llm.time.sleep", lambda seconds: None)
    path = tmp_path / "image.png"
    path.write_bytes(PNG)
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        if len(calls) == 1:
            return httpx.Response(400 if "response_format" in message else 429,
                                  json={"error": {"message": message}})
        return httpx.Response(200, json=completion())

    adapter = client(handler)
    adapter.chat("s", "u", schema={}, images=[path])
    assert len(calls) == 2
    assert calls[0]["messages"] == calls[1]["messages"]
    assert ("response_format" in calls[1]) == (message == "rate limited")


@pytest.mark.parametrize(("status", "message", "error"), [
    (400, "missing session header", BadRequestError),
    (429, "image service overloaded", RateLimitError),
])
def test_other_errors_keep_their_existing_type(tmp_path, status, message, error):
    path = tmp_path / "image.png"
    path.write_bytes(PNG)

    def handler(request):
        return httpx.Response(status, json={"error": {"message": message}})

    with pytest.raises(error):
        client(handler, retries=0).chat("s", "u", schema={}, images=[path])
