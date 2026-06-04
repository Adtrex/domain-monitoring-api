#!/usr/bin/env python
"""Test script to verify Groq integration is working."""

import os
import django
from pathlib import Path

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'domainscan.settings')
django.setup()

from api.remediation_enhancer import enhance_finding


def test_groq_enhancement():
    """Test enhancing a finding with Groq."""
    test_finding = {
        'title': 'Missing Content-Security-Policy Header',
        'category': 'Header',
        'risk_rating': 'High',
        'asset': 'example.com',
        'evidence': 'No CSP header detected on HTTP responses.',
        'recommendation': 'Deploy CSP header with default-src directive.',
    }

    print("=" * 70)
    print("🧪 Testing Groq Enhancement Integration")
    print("=" * 70)
    print("\n📋 Original Finding:")
    print(f"   Title: {test_finding['title']}")
    print(f"   Severity: {test_finding['risk_rating']}")
    print(f"   Category: {test_finding['category']}")
    print(f"   Evidence: {test_finding['evidence']}")

    print("\n⏳ Enhancing with Groq AI...")
    try:
        enhanced = enhance_finding(test_finding)

        print("\n✅ Enhancement Successful!\n")
        print("📝 Enhanced Issue Summary:")
        print(f"   {enhanced.get('issue_summary', 'N/A')}\n")

        print("🔧 Enhanced Remediation Steps:")
        steps = enhanced.get('remediation_steps', 'N/A')
        for line in steps.split('\n'):
            if line.strip():
                print(f"   {line}")

        print(f"\n⏱️  Risk Context:")
        print(f"   {enhanced.get('risk_context', 'N/A')}\n")

        print("=" * 70)
        print("✨ Groq integration is working correctly!")
        print("=" * 70)
        return True

    except Exception as e:
        print(f"\n❌ Enhancement Failed: {e}")
        print("\n⚠️  Troubleshooting:")
        print("   1. Check GROQ_API_KEY is set in .env")
        print("   2. Verify API key is valid at https://console.groq.com")
        print("   3. Install groq library: pip install groq")
        print("   4. Check internet connection")
        print("=" * 70)
        return False


if __name__ == '__main__':
    success = test_groq_enhancement()
    exit(0 if success else 1)
