"""
Gemini AI Analyzer
Sends raw scanner findings to Gemini for deep analysis:
enhanced severity, real-world impact, fix suggestions with code examples.
"""
import json
import logging
import time
from typing import List, Callable, Optional
import google.generativeai as genai

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior offensive and defensive cybersecurity expert specializing in web application security.
You conduct thorough security audits and provide actionable, developer-friendly remediation guidance."""

ANALYSIS_PROMPT = """Analyze the following raw security findings from an automated web scanner targeting: {target_url}

Your task:
1. Review each finding critically — confirm or escalate severity based on real-world exploitability
2. Write a clear, technical impact statement for each finding
3. Provide specific, copy-paste-ready fix recommendations (with code snippets where applicable)
4. Map each to OWASP Top 10 2021 and CWE
5. Assign a priority fix order (1 = fix immediately)
6. Write an executive summary with overall risk level and top 3 immediate actions

Return ONLY valid JSON in this exact structure:
{{
  "summary": {{
    "overall_risk": "Critical|High|Medium|Low",
    "risk_score": <integer 0-100>,
    "key_findings": ["<finding 1>", "<finding 2>", "<finding 3>"],
    "immediate_actions": ["<action 1>", "<action 2>", "<action 3>"],
    "executive_summary": "<2-3 sentence executive summary>"
  }},
  "findings": [
    {{
      "id": "<original finding id>",
      "enhanced_severity": "Critical|High|Medium|Low|Info",
      "risk_score": <integer 0-10>,
      "impact": "<real-world impact description>",
      "technical_details": "<in-depth technical explanation>",
      "fix_suggestion": "<specific remediation steps>",
      "code_example": "<code snippet showing the fix, or empty string>",
      "priority": <integer 1-N>,
      "references": ["<CVE or CWE reference>"]
    }}
  ]
}}

Raw findings (JSON):
{findings_json}

IMPORTANT: Return only the JSON object, no markdown fences, no explanation text."""


class GeminiAnalyzer:
    def __init__(self, api_key: str, model: str = "gemini-3.1-flash-lite-preview"):
        genai.configure(api_key=api_key)
        self.model_name = model
        self.model = genai.GenerativeModel(
            model_name=model,
            system_instruction=SYSTEM_PROMPT,
        )

    def _send(self, prompt: str, retries: int = 3) -> str:
        for attempt in range(retries):
            try:
                response = self.model.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.2,
                        max_output_tokens=8192,
                    ),
                )
                return response.text
            except Exception as e:
                logger.warning(f"Gemini attempt {attempt+1} failed: {e}")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
        raise RuntimeError("Gemini API failed after retries")

    def analyze(
        self,
        findings: List[dict],
        target_url: str,
        progress_callback: Callable = None,
        batch_size: int = 20,
    ) -> dict:
        if not findings:
            return {"summary": {}, "findings": []}

        all_enhanced_findings = []
        batches = [findings[i:i+batch_size] for i in range(0, len(findings), batch_size)]
        combined_summary = None

        for i, batch in enumerate(batches):
            if progress_callback:
                progress_callback(f"  Gemini: Analyzing batch {i+1}/{len(batches)} ({len(batch)} findings)...")

            # Slim down findings for the prompt to stay within token limits
            slim_batch = []
            for f in batch:
                slim_batch.append({
                    "id": f.get("id"),
                    "category": f.get("category"),
                    "type": f.get("type"),
                    "title": f.get("title"),
                    "description": f.get("description"),
                    "severity": f.get("severity"),
                    "affected_url": f.get("affected_url"),
                    "evidence": f.get("evidence", "")[:200],
                    "owasp": f.get("owasp", ""),
                    "cwe": f.get("cwe", ""),
                })

            prompt = ANALYSIS_PROMPT.format(
                target_url=target_url,
                findings_json=json.dumps(slim_batch, indent=2),
            )

            try:
                raw = self._send(prompt)
                # Strip markdown fences if present
                raw = raw.strip()
                if raw.startswith("```"):
                    raw = raw.split("```", 2)[1]
                    if raw.startswith("json"):
                        raw = raw[4:]
                    raw = raw.rsplit("```", 1)[0]

                parsed = json.loads(raw.strip())
                all_enhanced_findings.extend(parsed.get("findings", []))

                if combined_summary is None:
                    combined_summary = parsed.get("summary", {})

            except json.JSONDecodeError as e:
                logger.error(f"Gemini returned invalid JSON: {e}")
                if progress_callback:
                    progress_callback(f"  Gemini JSON parse error — falling back to raw findings for this batch")
                # Fall back: keep original findings for this batch
                for f in batch:
                    all_enhanced_findings.append({
                        "id": f.get("id"),
                        "enhanced_severity": f.get("severity"),
                        "risk_score": 5,
                        "impact": f.get("description"),
                        "technical_details": f.get("description"),
                        "fix_suggestion": f.get("fix_suggestion", ""),
                        "code_example": "",
                        "priority": len(all_enhanced_findings) + 1,
                        "references": [f.get("cwe", "")],
                    })

        # Merge Gemini enhanced data back into original findings
        enhanced_map = {ef["id"]: ef for ef in all_enhanced_findings if ef.get("id")}
        for f in findings:
            fid = f.get("id")
            if fid and fid in enhanced_map:
                ef = enhanced_map[fid]
                f["gemini_severity"] = ef.get("enhanced_severity", f.get("severity"))
                f["impact"] = ef.get("impact", "")
                f["technical_details"] = ef.get("technical_details", "")
                f["fix_suggestion"] = ef.get("fix_suggestion", f.get("fix_suggestion", ""))
                f["code_example"] = ef.get("code_example", "")
                f["priority"] = ef.get("priority", 99)
                f["gemini_risk_score"] = ef.get("risk_score", 0)
                f["references"] = ef.get("references", [])

        if progress_callback:
            progress_callback(f"  Gemini analysis complete — {len(all_enhanced_findings)} findings enhanced")

        return {
            "summary": combined_summary or {},
            "findings": all_enhanced_findings,
        }
