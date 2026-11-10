"""A local language model as a second reader of macro code (ADR-023).

The deterministic analysis decides. This package only lets a model that runs on THIS computer
(Ollama on a loopback address) read the recovered macro code and give advice, which may raise
suspicion and never lowers a verdict or decides one alone. Off unless LYNCEUS_LLM_REVIEW is set.
"""
