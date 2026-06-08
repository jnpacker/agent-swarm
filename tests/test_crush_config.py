"""Unit tests for CrushStrategy provider config and model derivation.

Covers:
- build_config_data(): providers present; vertex-anthropic models routed via inference.local
  through the standard anthropic provider (no separate vertex-anthropic provider entry)
- _derive_small_model(): correct small model for each provider/model combination
- is_valid_model(): vertex-anthropic/ prefix accepted
- get_default_model(): prefers vertex-anthropic when ADC available
- build_model_setup_cmd(): large/small model JSON written correctly
"""

import json
import shlex
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from swarmer.agent_tools.crush import CrushStrategy, _derive_small_model  # noqa: E402

_crush = CrushStrategy()


# ---------------------------------------------------------------------------
# build_config_data — providers
# ---------------------------------------------------------------------------

def _providers():
    data = _crush.build_config_data()
    cfg = json.loads(data["crush.json"])
    return cfg["providers"]


def test_vertex_anthropic_provider_absent():
    """vertex-anthropic openai-compat provider must not be present.

    Vertex Anthropic models are now routed through inference.local by the
    swarmer launch code (same approach as OpenCode).  The model is rewritten
    to anthropic/<id> and ANTHROPIC_BASE_URL is set to https://inference.local/v1,
    so the standard "anthropic" provider in crush.json handles those calls.
    A separate "vertex-anthropic" openai-compat entry with $VAR placeholders in
    the base_url is not needed and was the root cause of broken URLs.
    """
    assert "vertex-anthropic" not in _providers()


def test_anthropic_provider_handles_vertex_calls():
    """The anthropic provider is present and will handle inference.local-routed calls."""
    p = _providers()["anthropic"]
    assert p["type"] == "anthropic"
    assert p["api_key"] == "$ANTHROPIC_API_KEY"


def test_anthropic_provider_no_base_url_by_default():
    """Without inference.local, the anthropic provider has no base_url override."""
    data = _crush.build_config_data(model="anthropic/claude-sonnet-4-6")
    cfg = json.loads(data["crush.json"])
    assert "base_url" not in cfg["providers"]["anthropic"]


def test_inference_local_emits_only_anthropic_provider():
    """With use_inference_local=True, only the anthropic provider is present."""
    data = _crush.build_config_data(use_inference_local=True, model="anthropic/claude-sonnet-4-5")
    cfg = json.loads(data["crush.json"])
    assert list(cfg["providers"].keys()) == ["anthropic"]


def test_inference_local_anthropic_uses_dummy_key_and_base_url():
    """With use_inference_local=True, anthropic provider uses dummy key + inference.local base_url."""
    data = _crush.build_config_data(use_inference_local=True, model="anthropic/claude-sonnet-4-5")
    cfg = json.loads(data["crush.json"])
    p = cfg["providers"]["anthropic"]
    assert p.get("base_url") == "https://inference.local"
    assert p.get("api_key") == "sk-ant-inference-local-proxy"


def test_gemini_model_emits_only_gemini_provider():
    """Gemini model → only gemini provider, no anthropic/openai/vertexai."""
    data = _crush.build_config_data(model="gemini/gemini-3.5-flash")
    cfg = json.loads(data["crush.json"])
    assert list(cfg["providers"].keys()) == ["gemini"]


def test_openai_model_emits_only_openai_provider():
    """OpenAI model → only openai provider."""
    data = _crush.build_config_data(model="openai/gpt-4o")
    cfg = json.loads(data["crush.json"])
    assert list(cfg["providers"].keys()) == ["openai"]


def test_no_model_fallback_includes_all_providers():
    """No model → all providers included as fallback."""
    data = _crush.build_config_data()
    cfg = json.loads(data["crush.json"])
    assert set(cfg["providers"].keys()) == {"anthropic", "gemini", "openai", "vertexai"}


# ---------------------------------------------------------------------------
# build_config_data — other providers still present
# ---------------------------------------------------------------------------

def test_anthropic_provider_present():
    assert "anthropic" in _providers()


def test_vertexai_provider_present():
    assert "vertexai" in _providers()


def test_gemini_provider_present():
    assert "gemini" in _providers()


def test_openai_provider_present():
    assert "openai" in _providers()


# ---------------------------------------------------------------------------
# is_valid_model
# ---------------------------------------------------------------------------

def test_is_valid_model_vertex_anthropic():
    assert _crush.is_valid_model("vertex-anthropic/claude-sonnet-4-5")


def test_is_valid_model_vertex_anthropic_haiku():
    assert _crush.is_valid_model("vertex-anthropic/claude-haiku-4-5")


def test_is_valid_model_vertexai():
    assert _crush.is_valid_model("vertexai/gemini-3.5-flash")


def test_is_valid_model_anthropic():
    assert _crush.is_valid_model("anthropic/claude-sonnet-4-6")


def test_is_valid_model_invalid():
    assert not _crush.is_valid_model("google-vertex-anthropic/claude-sonnet-4-6@default")


# ---------------------------------------------------------------------------
# get_default_model
# ---------------------------------------------------------------------------

def test_get_default_model_adc_prefers_vertex_anthropic():
    assert _crush.get_default_model(has_adc=True, has_gemini=False) == "vertex-anthropic/claude-sonnet-4-6"


def test_get_default_model_no_adc_prefers_gemini():
    assert _crush.get_default_model(has_adc=False, has_gemini=True) == "gemini/gemini-3.5-flash"


def test_get_default_model_no_creds_returns_empty():
    assert _crush.get_default_model(has_adc=False, has_gemini=False) == ""


# ---------------------------------------------------------------------------
# _derive_small_model
# ---------------------------------------------------------------------------

def test_derive_small_vertex_anthropic_sonnet_gives_haiku():
    small = _derive_small_model("vertex-anthropic/claude-sonnet-4-6")
    assert small == "vertex-anthropic/claude-haiku-4-5"


def test_derive_small_vertex_anthropic_opus_gives_sonnet():
    small = _derive_small_model("vertex-anthropic/claude-opus-4-6")
    assert small == "vertex-anthropic/claude-sonnet-4-6"


def test_derive_small_vertexai_sonnet_gives_haiku():
    small = _derive_small_model("vertexai/claude-sonnet-4-6")
    assert small == "vertexai/claude-haiku-4-5-20251001"


def test_derive_small_anthropic_sonnet_gives_haiku():
    small = _derive_small_model("anthropic/claude-sonnet-4-6")
    assert small == "anthropic/claude-haiku-3.5"


def test_derive_small_gemini_pro_gives_flash():
    small = _derive_small_model("vertexai/gemini-3.5-pro")
    assert small == "vertexai/gemini-3.5-flash"


def test_derive_small_haiku_returns_none():
    # Already at the small tier — no smaller model
    assert _derive_small_model("vertex-anthropic/claude-haiku-4-5") is None


def test_derive_small_no_slash_returns_none():
    assert _derive_small_model("unknownmodel") is None


# ---------------------------------------------------------------------------
# build_model_setup_cmd — vertex-anthropic large/small written correctly
# ---------------------------------------------------------------------------

def _parse_model_setup_json(cmd: str) -> dict:
    """Extract the JSON payload from build_model_setup_cmd output.

    The command is: ... printf '%s' '<json>' > ...
    shlex.split on the printf argument portion gives ['%s', '<json>'].
    """
    printf_part = cmd.split("printf")[1].split(">")[0]
    parts = shlex.split(printf_part)
    return json.loads(parts[1])  # parts[0] is '%s', parts[1] is the JSON


def test_model_setup_cmd_vertex_anthropic_large():
    cmd = _crush.build_model_setup_cmd("vertex-anthropic/claude-sonnet-4-6")
    cfg = _parse_model_setup_json(cmd)
    assert cfg["models"]["large"]["provider"] == "vertex-anthropic"
    assert cfg["models"]["large"]["model"] == "claude-sonnet-4-6"


def test_model_setup_cmd_vertex_anthropic_small_derived():
    cmd = _crush.build_model_setup_cmd("vertex-anthropic/claude-sonnet-4-6")
    cfg = _parse_model_setup_json(cmd)
    assert cfg["models"]["small"]["provider"] == "vertex-anthropic"
    assert cfg["models"]["small"]["model"] == "claude-haiku-4-5"
