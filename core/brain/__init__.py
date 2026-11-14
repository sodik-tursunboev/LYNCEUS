"""The brain (AI1): a local model reads what the rules cannot, and code checks every answer.

The model is briefed, never trained here; it answers a closed form (enums and short quotes only).
Code then checks each claim against the evidence it came from: a quote must occur in the page or
mail text, a brand must not own the page's domain, an endpoint must be one the code found. Only a
checked claim becomes a signal, in its own category `brain` (capped: alone it reaches SUSPICIOUS at
most; next to one independent rule category it can reach MALICIOUS; owner's decision, AI1). It never
lowers a verdict, never duplicates a rule that already fired on the same thing, and nothing the
model writes in free text is stored or shown: only finding codes, brand names and counts.

Local only (core/llm/ollama.py refuses any address but this computer's), off unless
LYNCEUS_BRAIN=true, and every test runs against a fake model.
"""
