def build_narrative_prompt(best_path, node_labels, language="english"):
    steps = " -> ".join(node_labels.get(n, n) for n in best_path["path"])
    return f"""You are PRAWL explaining a real attack path to a non-technical Indian business owner.
The verified attack path is: {steps}
Confidence: {int(best_path['confidence']*100)}%.
Explain in 3-4 plain sentences how an attacker walks this exact path, ending at a customer-data breach.
Do NOT invent any step not in the path above.
Language: {language}."""


def generate_narrative(best_path, node_labels, language, groq_key=None):
    """
    Generate a plain-language narrative of the attack path.
    Uses Groq if api key is available, falls back to rule-based text.
    """
    if not best_path:
        return ""

    prompt = build_narrative_prompt(best_path, node_labels, language)

    if groq_key:
        try:
            import httpx
            from groq import Groq
            client = Groq(api_key=groq_key, http_client=httpx.Client())
            r = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=250
            )
            return r.choices[0].message.content.strip()
        except Exception:
            pass

    # Fallback: rule-based narrative
    steps = " -> ".join(node_labels.get(n, n.replace("_", " ").title()) for n in best_path["path"])
    confidence_pct = int(best_path['confidence'] * 100)
    return (
        f"An attacker could follow this path: {steps}. "
        f"This attack chain has a {confidence_pct}% confidence of succeeding based on the verified findings. "
        f"Each step in this path has been confirmed by actual scan results on your website. "
        f"Fix the first finding in this chain to break the entire attack path."
    )
