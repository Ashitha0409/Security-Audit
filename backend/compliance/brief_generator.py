import os

LANGUAGE_INSTRUCTIONS = {
    'english': 'Plain English.',
    'hindi':   'हिंदी में लिखें।',
    'telugu':  'తెలుగులో రాయండి.',
    'tamil':   'தமிழில் எழுதுங்கள்.',
    'kannada': 'ಕನ್ನಡದಲ್ಲಿ ಬರೆಯಿರಿ.',
    'marathi': 'मराठीत लिहा.',
    'bengali': 'বাংলায় লিখুন।',
}


def build_compliance_prompt(url, hits, readiness_score, language="english"):
    gap_lines = "\n".join(
        f"- {h['clause']} ({h['law']}): {h['status'].upper()} — up to Rs.{h['penalty_ceiling_inr']//10000000} crore. {h['rationale']}"
        for h in hits
    )
    return f"""You are PRAWL, a compliance assistant for Indian small businesses.
Website: {url} | DPDP Readiness: {readiness_score}/100
Compliance gaps mapped to law:
{gap_lines or 'No mapped compliance gaps.'}

Write 4 short sentences for a non-technical Indian business owner:
1. State the readiness score and the single biggest legal risk.
2. Name the most urgent obligation and its rupee penalty ceiling.
3. Mention that a customer-data breach triggers BOTH a 6-hour CERT-In clock and a 72-hour DPDP clock.
4. Give one concrete action to take this week.
End with: "This is indicative guidance, not legal advice."
Language: {LANGUAGE_INSTRUCTIONS.get(language, 'Plain English.')}.
Plain paragraph. No jargon. No bullet points."""


def generate_compliance_brief(url, hits, readiness_score, language="english"):
    """
    Generate a compliance brief for the given URL and obligation hits.
    Uses Groq if GROQ_API_KEY is set, falls back to rule-based text.
    """
    if not hits:
        return (
            f"Your DPDP readiness score is {readiness_score}/100 — no compliance gaps detected in this scan. "
            f"Continue scanning regularly and maintain your security headers and encryption settings. "
            f"Remember that a future data breach would trigger both a 6-hour CERT-In reporting deadline and a 72-hour DPDP Board notification. "
            f"This is indicative guidance, not legal advice."
        )

    prompt = build_compliance_prompt(url, hits, readiness_score, language)
    groq_key = os.environ.get('GROQ_API_KEY', '')

    if groq_key:
        try:
            import httpx
            from groq import Groq
            client = Groq(api_key=groq_key, http_client=httpx.Client())
            r = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300
            )
            return r.choices[0].message.content.strip()
        except Exception:
            pass

    # Rule-based fallback
    worst = max(hits, key=lambda h: h['penalty_ceiling_inr'])
    gap_hits = [h for h in hits if h['status'] == 'gap']
    most_urgent = max(gap_hits, key=lambda h: h['penalty_ceiling_inr']) if gap_hits else worst

    return (
        f"Your DPDP readiness score is {readiness_score}/100 — this indicates significant legal exposure under Indian data protection law. "
        f"Your most urgent obligation is under {most_urgent['clause']} ({most_urgent['law']}) with a penalty ceiling up to "
        f"Rs.{most_urgent['penalty_ceiling_inr']//10000000} crore ({most_urgent['rationale']}). "
        f"Be aware that any customer data breach triggers two simultaneous clocks: a 6-hour CERT-In cyber-incident reporting deadline "
        f"and a 72-hour DPDP Board notification deadline — both carry separate penalties. "
        f"Fix your highest-priority security finding this week to reduce both your technical and legal risk. "
        f"This is indicative guidance, not legal advice."
    )
