"""AI-powered remediation enhancement using Groq LLM."""

import json
import logging
from typing import Dict, Optional
import os

logger = logging.getLogger(__name__)


def get_groq_client():
    """Initialize and return Groq client."""
    try:
        from groq import Groq
        api_key = os.getenv('GROQ_API_KEY', '').strip()
        if not api_key:
            logger.debug("GROQ_API_KEY not configured, AI enhancement disabled")
            return None
        return Groq(api_key=api_key)
    except ImportError:
        logger.debug("Groq library not installed. Install with: pip install groq")
        return None
    except Exception as e:
        logger.warning(f"Failed to initialize Groq client: {e}")
        return None


def generate_issue_summary(finding: Dict) -> str:
    """Generate detailed 'About this Issue' text using Groq."""
    client = get_groq_client()
    if not client:
        return finding.get('evidence', 'Security issue identified.')

    title = finding.get('title', 'Unknown Finding')
    category = finding.get('category', 'Other')
    risk_rating = finding.get('risk_rating', 'Medium')
    evidence = finding.get('evidence', '')

    prompt = f"""You are a cybersecurity expert. Generate a concise "About this Issue" explanation (2-3 sentences) for a security finding.

Finding Title: {title}
Category: {category}
Severity: {risk_rating}
Description: {evidence}

Explain what the vulnerability is, why it's a problem, and business impact. Keep it clear and technical but accessible. No markdown."""

    try:
        message = client.chat.completions.create(
            model=os.getenv('GROQ_MODEL', 'llama-3.3-70b-versatile'),
            max_tokens=200,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return message.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"Groq API error generating issue summary: {e}")
        return evidence or 'Security issue identified.'


def generate_remediation_steps(finding: Dict) -> str:
    """Generate actionable remediation steps using Groq."""
    client = get_groq_client()
    if not client:
        return finding.get('recommendation', 'Review and remediate this finding.')

    title = finding.get('title', 'Unknown Finding')
    category = finding.get('category', 'Other')
    risk_rating = finding.get('risk_rating', 'Medium')
    asset = finding.get('asset', 'unknown asset')

    prompt = f"""You are a cybersecurity remediation expert. Generate specific, actionable remediation steps for a security finding.

Finding: {title}
Category: {category}
Severity: {risk_rating}
Affected Asset: {asset}

Provide 3-4 concrete remediation steps that are:
- Specific and actionable
- Prioritized by impact
- Include timeline context based on severity
- Include testing/validation step

Format as numbered list. No markdown, plain text only."""

    try:
        message = client.chat.completions.create(
            model=os.getenv('GROQ_MODEL', 'llama-3.3-70b-versatile'),
            max_tokens=300,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return message.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"Groq API error generating remediation steps: {e}")
        return finding.get('recommendation', 'Review vendor guidance and apply recommended fixes.')


def enhance_finding(finding: Dict) -> Dict:
    """Enhance a finding with AI-generated issue summary and remediation steps."""
    enhanced = finding.copy()

    # Generate detailed issue summary
    enhanced['issue_summary'] = generate_issue_summary(finding)

    # Generate detailed remediation steps
    enhanced['remediation_steps'] = generate_remediation_steps(finding)

    # Add risk context based on severity
    risk_rating = finding.get('risk_rating', 'Low').lower()
    risk_contexts = {
        'critical': 'Escalate immediately — patch, verify, and confirm closure within 24 hours.',
        'high': 'Prioritise this fix — target remediation within 7 days.',
        'medium': 'Schedule remediation within the next sprint or 30-day window.',
        'low': 'Address during routine hardening and confirm in the next scheduled security review.',
    }
    enhanced['risk_context'] = risk_contexts.get(risk_rating, risk_contexts['low'])

    return enhanced


def enhance_findings_batch(findings: list) -> list:
    """Enhance multiple findings with AI-generated content."""
    enhanced_findings = []

    for finding in findings:
        try:
            enhanced = enhance_finding(finding)
            enhanced_findings.append(enhanced)
        except Exception as e:
            logger.error(f"Error enhancing finding {finding.get('title')}: {e}")
            # Fall back to original finding if enhancement fails
            enhanced_findings.append(finding)

    return enhanced_findings
