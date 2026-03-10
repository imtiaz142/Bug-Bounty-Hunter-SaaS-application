from typing import Optional

from app.llm.base import LLMProvider


def get_llm_provider(
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Optional[LLMProvider]:
    """Create and return the requested LLM provider, or None.

    Args:
        provider: One of ``"claude"`` or ``"openai"``.
        api_key: The API key for the chosen provider.

    Returns:
        An :class:`LLMProvider` instance, or ``None`` when the provider
        is unrecognised or the api_key is missing.
    """
    if not provider or not api_key:
        return None

    provider = provider.strip().lower()

    if provider == "claude":
        from app.llm.claude_provider import ClaudeProvider
        return ClaudeProvider(api_key=api_key)

    if provider == "openai":
        from app.llm.openai_provider import OpenAIProvider
        return OpenAIProvider(api_key=api_key)

    return None
