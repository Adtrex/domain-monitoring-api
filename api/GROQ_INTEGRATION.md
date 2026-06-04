# Groq AI Integration for Report Enhancement

## Overview

This integration uses **Groq's LLaMA 3.3 70B model** to automatically generate enhanced security finding descriptions and remediation steps for vulnerability reports.

## Configuration Status ✅

Your environment is **fully configured**:

```
✓ GROQ_API_KEY: Configured in .env
✓ GROQ_MODEL: llama-3.3-70b-versatile
✓ Settings: Loaded in domainscan/settings.py
✓ Integration: Active in api/remediation_enhancer.py
```

## How It Works

### 1. **Finding Extraction**
The report generation pipeline extracts findings from your database and structures them:
```python
{
    'title': 'Missing Content-Security-Policy Header',
    'category': 'Header',
    'risk_rating': 'High',
    'asset': 'example.com',
    'evidence': 'No CSP header detected...',
    'recommendation': 'Deploy CSP header...'
}
```

### 2. **AI Enhancement**
For each finding, Groq generates three pieces of content:

#### A. Issue Summary
- **2-3 sentence explanation** of what the vulnerability is
- **Why it matters** to security posture
- **Business impact** context
```
Example: "A Content Security Policy header is missing, leaving the 
site vulnerable to XSS attacks where malicious scripts can be injected..."
```

#### B. Remediation Steps
- **3-4 concrete, actionable steps**
- **Prioritized by impact**
- **Testing/validation included**
```
Example:
1. Deploy CSP header with default-src 'self' directive
2. Whitelist trusted sources for scripts and styles
3. Enable report-uri for violation monitoring
4. Test in report-only mode before enforcement
```

#### C. Risk Context
- **Severity-based timeline** (automatically assigned)
```
Critical: "Escalate immediately — patch within 24 hours"
High:     "Prioritise — remediate within 7 days"
Medium:   "Schedule within 30 days"
Low:      "Address during routine hardening"
```

### 3. **Report Generation**
Enhanced findings are used in PDF/DOCX reports with structured layout.

## Testing the Integration

### Quick Test
```bash
python api/test_groq_integration.py
```

Expected output:
```
🧪 Testing Groq Enhancement Integration
========================================
📋 Original Finding:
   Title: Missing Content-Security-Policy Header
   Severity: High
   ...

⏳ Enhancing with Groq AI...

✅ Enhancement Successful!
📝 Enhanced Issue Summary:
   [AI-generated explanation]

🔧 Enhanced Remediation Steps:
   1. [Step 1]
   2. [Step 2]
   ...
```

### Integration Test in Report
1. Generate a report via API:
```bash
curl "http://localhost:8000/api/report/export/?scan_id=1&format=pdf"
```

2. Check logs for Groq calls:
```bash
grep -i "groq\|enhancement" logs/cerrt.log
```

## Graceful Degradation

If Groq is unavailable:
- ✅ Reports still generate successfully
- ⚠️ Findings use base template text instead of AI-enhanced content
- 📋 No API errors or failures
- 🔄 Retries automatically enabled

This means:
- Missing API key? Reports work with base templates
- Network timeout? Uses fallback text
- Rate limited? Still generates readable reports

## Performance Considerations

### Processing Time
- **Per finding**: ~1-2 seconds (API call + generation)
- **Batch (10 findings)**: ~10-20 seconds total
- **Caching**: Not implemented (each report generation is fresh)

### API Usage
- **Requests per report**: 1 per finding (3 if enhanced)
- **Tokens per request**: ~100-300 input, ~150-300 output
- **Cost**: Very low (Groq is free tier for development)

### Optimization Opportunities
- [ ] Cache generated content by finding title+severity
- [ ] Batch API calls (multiple findings per request)
- [ ] Async processing for large reports
- [ ] Database storage of enhancements (reuse across reports)

## Troubleshooting

### Issue: "Groq library not installed"
```bash
pip install groq
```

### Issue: "GROQ_API_KEY not configured"
Check `.env` file:
```
GROQ_API_KEY=gsk_xxxxx...
```

### Issue: "API Error" in logs
- Verify key is active: https://console.groq.com/keys
- Check network connectivity
- Review Groq status page

### Issue: Enhancement takes too long
- This is normal (1-2s per finding)
- For reports with 50+ findings, expect 1-2 minutes
- Consider caching for production

## Files Modified

### New Files
- `api/remediation_enhancer.py` - Core enhancement logic
- `api/test_groq_integration.py` - Test script
- `api/GROQ_INTEGRATION.md` - This documentation

### Modified Files
- `api/report_summary_views.py` - Added enhancement call in findings loop

## API Reference

### enhance_finding(finding: Dict) → Dict
Enhances a single finding with AI-generated content.

```python
from api.remediation_enhancer import enhance_finding

finding = {
    'title': 'Missing Header',
    'category': 'Header',
    'risk_rating': 'High',
    'asset': 'example.com',
    'evidence': 'Header not found',
    'recommendation': 'Add header'
}

enhanced = enhance_finding(finding)
# Returns original dict + new keys:
# - issue_summary: AI-generated explanation
# - remediation_steps: AI-generated steps
# - risk_context: Severity-based timeline
```

### enhance_findings_batch(findings: List[Dict]) → List[Dict]
Enhances multiple findings (batch operation).

```python
from api.remediation_enhancer import enhance_findings_batch

findings = [finding1, finding2, ...]
enhanced = enhance_findings_batch(findings)
```

## Future Enhancements

1. **Caching Layer**
   - Store enhanced content in ReportSummaryFinding
   - Reuse across reports
   - Reduce API calls

2. **Custom Prompts**
   - Organization-specific remediation guidance
   - Industry-specific context (healthcare, finance, etc.)
   - Language support

3. **Async Processing**
   - Queue findings for background enhancement
   - Don't block report generation
   - Faster user experience

4. **Quality Metrics**
   - Track enhancement quality
   - A/B test different prompts
   - Measure impact on remediation rates

## Support

For issues or questions:
1. Check logs: `tail -f logs/cerrt.log`
2. Run test: `python api/test_groq_integration.py`
3. Review this doc for troubleshooting
4. Contact: toluadekunte@gmail.com
