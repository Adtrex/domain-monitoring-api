# Domain Security Posture API Integration

## Endpoint
```
GET /api/domains/{domain_id}/posture/
```

## Description
Retrieves comprehensive security posture summary for a domain, including:
- Overall risk rating and findings summary
- Latest scan information
- Security check status (Email, SSL/TLS, DNS, Headers, Libraries)
- All findings grouped by category and severity
- List of scanned assets under the domain

## Response Format
```json
{
  "domain_id": 1,
  "domain": "example.com",
  "status": "completed",
  "last_scan": "2024-04-24T15:30:00Z",
  "last_scan_at": "2024-04-24T15:30:00Z",
  "last_scan_date": "2024-04-24",
  "last_scan_time": "15:30:00",
  "scan_duration_seconds": 1250,
  "overall_risk_rating": "High",
  "findings_summary": {
    "total": 24,
    "critical": 2,
    "high": 5,
    "medium": 10,
    "low": 7
  },
  "findings_by_category": {
    "SSL": {
      "count": 8,
      "by_severity": {
        "critical": 0,
        "high": 3,
        "medium": 4,
        "low": 1
      },
      "issues": [
        {
          "id": 42,
          "title": "Weak SSL/TLS Configuration",
          "category": "SSL",
          "risk_rating": "High",
          "asset": 5,
          "status": "open"
        }
      ]
    },
    "DNS": {
      "count": 5,
      "by_severity": { },
      "issues": [ ]
    },
    "Email": {
      "count": 3,
      "by_severity": { },
      "issues": [ ]
    }
  },
  "email_security": {
    "spf": "pass",
    "dkim": "fail",
    "dmarc": "not_checked",
    "total_checks": 12
  },
  "ssl_tls": {
    "passed": 8,
    "failed": 4,
    "score": 67,
    "total_checks": 12
  },
  "dns_security": {
    "total_checks": 6,
    "issues": 2
  },
  "security_headers": {
    "present": 5,
    "missing": 7,
    "total": 12
  },
  "frontend_libraries": {
    "up_to_date": 45,
    "outdated": 12,
    "vulnerable": 3,
    "total": 60
  },
  "assets_scanned": [
    {
      "id": 1,
      "value": "example.com",
      "type": "root_domain",
      "issues_found": 8
    },
    {
      "id": 5,
      "value": "api.example.com",
      "type": "subdomain",
      "issues_found": 5
    },
    {
      "id": 12,
      "value": "mail.example.com",
      "type": "subdomain",
      "issues_found": 11
    }
  ]
}
```

## Error Response (No Scans)
```json
{
  "domain_id": 1,
  "domain": "example.com",
  "status": "no_scans",
  "message": "No completed scans found for this domain",
  "last_scan_at": null,
  "last_scan_date": null,
  "last_scan_time": null,
  "assets": []
}
```

## Usage Example (JavaScript/React)

### Basic Fetch
```javascript
// Fetch domain posture
async function getDomainPosture(domainId) {
  try {
    const response = await fetch(`/api/domains/${domainId}/posture/`);
    const data = await response.json();
    
    if (data.status === 'no_scans') {
      return {
        ready: false,
        message: 'No scans available yet. Run a scan to get started.'
      };
    }
    
    return {
      ready: true,
      domain: data.domain,
      risk: data.overall_risk_rating,
      lastScan: data.last_scan_at ? new Date(data.last_scan_at) : null,
      lastScanDate: data.last_scan_date,
      lastScanTime: data.last_scan_time,
      findings: data.findings_summary.total,
      critical: data.findings_summary.critical,
      email: data.email_security,
      ssl: data.ssl_tls,
      dns: data.dns_security,
      headers: data.security_headers,
      libraries: data.frontend_libraries,
      assets: data.assets_scanned
    };
  } catch (error) {
    console.error('Failed to fetch domain posture:', error);
    return { ready: false, error: error.message };
  }
}
```

### React Component Example
```javascript
import React, { useState, useEffect } from 'react';

function DomainPostureDashboard({ domainId }) {
  const [posture, setPosture] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchPosture = async () => {
      try {
        const response = await fetch(`/api/domains/${domainId}/posture/`);
        if (!response.ok) {
          throw new Error(`API error: ${response.status}`);
        }
        const data = await response.json();
        setPosture(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchPosture();
  }, [domainId]);

  if (loading) return <div>Loading posture data...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!posture || posture.status === 'no_scans') {
    return <div>No scans available. Run a scan to get started.</div>;
  }

  return (
    <div className="domain-posture-dashboard">
      {/* Domain Header */}
      <div className="domain-header">
        <h1>{posture.domain}</h1>
        <p>
          Last Scanned: {posture.last_scan_date && posture.last_scan_time
            ? `${posture.last_scan_date} ${posture.last_scan_time}`
            : 'N/A'}
        </p>
      </div>

      {/* Risk Rating Badge */}
      <div className={`risk-badge risk-${posture.overall_risk_rating.toLowerCase()}`}>
        Overall Risk: {posture.overall_risk_rating}
      </div>

      {/* Findings Summary */}
      <div className="findings-summary">
        <h2>Findings Summary</h2>
        <div className="metrics-grid">
          <div className="metric">
            <span className="label">Total Findings</span>
            <span className="value">{posture.findings_summary.total}</span>
          </div>
          <div className="metric critical">
            <span className="label">Critical</span>
            <span className="value">{posture.findings_summary.critical}</span>
          </div>
          <div className="metric high">
            <span className="label">High</span>
            <span className="value">{posture.findings_summary.high}</span>
          </div>
          <div className="metric medium">
            <span className="label">Medium</span>
            <span className="value">{posture.findings_summary.medium}</span>
          </div>
          <div className="metric low">
            <span className="label">Low</span>
            <span className="value">{posture.findings_summary.low}</span>
          </div>
        </div>
      </div>

      {/* Security Checks Status */}
      <div className="security-status">
        <h2>Security Checks</h2>
        
        {/* Email Security */}
        <div className="check-group">
          <h3>Email Security</h3>
          <div className="check-item">
            <span className={`status ${posture.email_security.spf}`}>SPF:</span>
            <span>{posture.email_security.spf.toUpperCase()}</span>
          </div>
          <div className="check-item">
            <span className={`status ${posture.email_security.dkim}`}>DKIM:</span>
            <span>{posture.email_security.dkim.toUpperCase()}</span>
          </div>
          <div className="check-item">
            <span className={`status ${posture.email_security.dmarc}`}>DMARC:</span>
            <span>{posture.email_security.dmarc.toUpperCase()}</span>
          </div>
        </div>

        {/* SSL/TLS */}
        <div className="check-group">
          <h3>SSL/TLS Configuration</h3>
          <div className="progress-bar">
            <div 
              className="progress-fill" 
              style={{ width: `${posture.ssl_tls.score}%` }}
            ></div>
          </div>
          <p>{posture.ssl_tls.score}% Secure ({posture.ssl_tls.passed}/{posture.ssl_tls.total_checks} checks passed)</p>
        </div>

        {/* DNS Security */}
        <div className="check-group">
          <h3>DNS Security</h3>
          <p>{posture.dns_security.total_checks} checks | {posture.dns_security.issues} issues</p>
        </div>

        {/* Security Headers */}
        <div className="check-group">
          <h3>Security Headers</h3>
          <p>{posture.security_headers.present} present | {posture.security_headers.missing} missing</p>
        </div>

        {/* Frontend Libraries */}
        <div className="check-group">
          <h3>Frontend Libraries</h3>
          <p>
            {posture.frontend_libraries.up_to_date} up-to-date | 
            {posture.frontend_libraries.outdated} outdated | 
            {posture.frontend_libraries.vulnerable} vulnerable
          </p>
        </div>
      </div>

      {/* Findings by Category */}
      <div className="findings-by-category">
        <h2>Issues by Category</h2>
        {Object.entries(posture.findings_by_category).map(([category, details]) => (
          <div key={category} className="category-section">
            <h3>{category} ({details.count})</h3>
            <div className="severity-breakdown">
              {details.by_severity.critical > 0 && <span className="critical">{details.by_severity.critical} Critical</span>}
              {details.by_severity.high > 0 && <span className="high">{details.by_severity.high} High</span>}
              {details.by_severity.medium > 0 && <span className="medium">{details.by_severity.medium} Medium</span>}
              {details.by_severity.low > 0 && <span className="low">{details.by_severity.low} Low</span>}
            </div>
            <div className="issues-list">
              {details.issues.slice(0, 5).map(issue => (
                <div key={issue.id} className={`issue severity-${issue.risk_rating.toLowerCase()}`}>
                  <strong>{issue.title}</strong>
                  <p>Asset: {issue.asset}</p>
                </div>
              ))}
              {details.issues.length > 5 && <p className="more-issues">+{details.issues.length - 5} more</p>}
            </div>
          </div>
        ))}
      </div>

      {/* Scanned Assets */}
      <div className="assets-section">
        <h2>Scanned Assets</h2>
        <table>
          <thead>
            <tr>
              <th>Asset</th>
              <th>Type</th>
              <th>Issues Found</th>
            </tr>
          </thead>
          <tbody>
            {posture.assets_scanned.map(asset => (
              <tr key={asset.id}>
                <td>{asset.value}</td>
                <td>{asset.type.replace('_', ' ')}</td>
                <td className={asset.issues_found > 0 ? 'has-issues' : 'clean'}>
                  {asset.issues_found}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default DomainPostureDashboard;
```

## Key Integration Points

### 1. Risk Rating Badge
Use `overall_risk_rating` to color-code dashboard:
- **Critical** (Red): #DC3545
- **High** (Orange): #FD7E14
- **Medium** (Yellow): #FFC107
- **Low** (Green): #28A745

### 2. Summary Cards
Display key metrics as cards:
- Total findings & breakdown by severity
- Email security status (SPF/DKIM/DMARC)
- SSL/TLS score percentage
- Missing security headers count
- Vulnerable libraries count

### 3. Issues List
Use `findings_by_category` to populate:
- Collapsible sections per category
- Show top 10 issues per category
- Link to detailed issue view for drilling down

### 4. Asset Breakdown
Show list of scanned subdomains/assets:
- Display asset value, type, and issue count
- Allow drilling into specific asset details
- Show which assets have the most issues

### 5. Last Scan Info
Display context about the scan:
- `last_scan` timestamp
- `scan_duration_seconds` for user context
- Status indicator (completed)

### 6. Polling/Refresh
Call endpoint periodically:
- On-demand refresh button
- Auto-refresh every 60 seconds (configurable)
- Show "last updated" timestamp

## Response Time
Typically **< 500ms** (database query on indexed fields: domain, scan status, latest scan)

## Authentication
No authentication required by default. Adjust permissions in Django settings as needed for your security model.

## Status Codes
- **200 OK**: Successfully retrieved posture data
- **404 Not Found**: Domain does not exist
- **500 Server Error**: Backend error

## Example CSS for Styling
```css
.domain-posture-dashboard {
  padding: 20px;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

.risk-badge {
  display: inline-block;
  padding: 10px 16px;
  border-radius: 4px;
  font-weight: bold;
  margin: 20px 0;
}

.risk-badge.risk-critical { background: #DC3545; color: white; }
.risk-badge.risk-high { background: #FD7E14; color: white; }
.risk-badge.risk-medium { background: #FFC107; color: black; }
.risk-badge.risk-low { background: #28A745; color: white; }

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 15px;
  margin: 20px 0;
}

.metric {
  background: #f5f5f5;
  padding: 15px;
  border-radius: 4px;
  text-align: center;
}

.metric .label {
  display: block;
  font-size: 12px;
  color: #666;
  margin-bottom: 5px;
}

.metric .value {
  display: block;
  font-size: 24px;
  font-weight: bold;
  color: #333;
}

.metric.critical { border-left: 4px solid #DC3545; }
.metric.high { border-left: 4px solid #FD7E14; }
.metric.medium { border-left: 4px solid #FFC107; }
.metric.low { border-left: 4px solid #28A745; }

.check-group {
  background: #f5f5f5;
  padding: 15px;
  border-radius: 4px;
  margin: 15px 0;
}

.check-item {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  border-bottom: 1px solid #ddd;
}

.status.pass { color: #28A745; font-weight: bold; }
.status.fail { color: #DC3545; font-weight: bold; }
.status.not_checked { color: #999; font-weight: bold; }

.progress-bar {
  width: 100%;
  height: 20px;
  background: #ddd;
  border-radius: 4px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #28A745, #FFC107, #FD7E14, #DC3545);
  transition: width 0.3s ease;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 15px;
}

table th {
  background: #f5f5f5;
  padding: 12px;
  text-align: left;
  font-weight: bold;
  border-bottom: 2px solid #ddd;
}

table td {
  padding: 12px;
  border-bottom: 1px solid #ddd;
}

table td.has-issues { color: #DC3545; font-weight: bold; }
table td.clean { color: #28A745; font-weight: bold; }
```

## Notes
- The endpoint returns data from the **latest completed scan** for the domain
- If no completed scans exist, status will be `no_scans`
- Findings are aggregated across all assets (subdomains) under the domain
- Score calculations are automated (SSL score = passed checks / total checks * 100)
- Email status maps to: `pass`, `fail`, or `not_checked`
