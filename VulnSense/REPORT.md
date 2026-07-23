# VulnSense Project Report

## 1. Overview

VulnSense is a Flask-based, context-aware web vulnerability assessment tool. It accepts a target URL, performs read-only HTTP and HTTPS checks, maps findings to OWASP Top 10 categories, applies contextual risk scoring, and provides a browser dashboard with PDF export.

The scanner is intended for systems the operator owns or is explicitly authorized to assess. It is not a penetration-testing exploit framework and does not perform brute force, authentication bypass, destructive actions, or multi-stage attack chains.

## 2. Project Structure

```text
VulnSense/
  main.py                    Flask server entry point
  requirements.txt           Runtime dependencies
  REPORT.md                  This project report
  core/
    __init__.py              Package exports
    scanner.py               Passive scanner and safe detection checks
    risk_engine.py           Business-context score calculation
    report_generator.py      ReportLab PDF generation
  gui/
    __init__.py              Web app exports
    app.py                   Flask dashboard, scan route, and PDF route
  venv/                      Windows virtual environment
```

The Python source is portable across Windows and Linux. The included `venv` is platform-specific; on Linux, create a Linux virtual environment with `python3 -m venv venv` and install `requirements.txt`.

## 3. How to Run

### Windows

```powershell
cd "C:\Users\ranat\Desktop\vuln sense\VulnSense"
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe main.py
```

Open `http://127.0.0.1:5050` in a browser.

### Linux

```bash
cd VulnSense
python3 -m venv venv
. venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Open `http://127.0.0.1:5050` in a browser.

## 4. Application Flow

1. The user enters a target URL in the Flask dashboard.
2. `gui/app.py` creates a fixed internal business context and starts a scan.
3. `core/scanner.py` fetches the target and runs independent checks.
4. Each check catches its own errors and returns a low-severity reliability finding instead of crashing the scan.
5. `core/risk_engine.py` calculates a contextual score for each finding.
6. The dashboard displays risk, category, OWASP mapping, score, description, justification, and recommendation.
7. The export endpoint uses `core/report_generator.py` to create a PDF report.

## 5. OWASP Coverage

### A01:2021 - Broken Access Control

The scanner requests a small list of common sensitive paths without credentials. It reports only when the response is HTTP 200 and contains path-specific sensitive indicators. Generic pages, normal login pages, redirects, 401, 403, and 404 responses are filtered out.

This is a reachable-without-auth heuristic, not full authorization testing. Complete access-control testing requires authenticated sessions, multiple roles, object identifiers, and application-specific workflows.

### A02:2021 - Cryptographic Failures

Checks include:

- Plain HTTP target detection.
- Weak negotiated TLS protocol detection.
- Certificate expiry when certificate parsing is available.
- HTTPS pages submitting forms to HTTP actions.
- Password inputs without restrictive autocomplete values.
- Cookie flags such as Secure, HttpOnly, and SameSite.

### A03:2021 - Injection

The scanner performs limited detection-only probes when query parameters or discoverable GET form fields exist:

- One harmless reflected-marker request per discovered parameter.
- One single-quote SQL error-indicator request per discovered parameter.
- Detection of common database error strings.

These checks identify possible reflected XSS or SQL error leakage. They do not prove exploitability and do not execute scripts, dump databases, bypass authentication, or chain attacks.

### A04:2021 - Insecure Design

Heuristics include:

- Login-like page over HTTP without visible CAPTCHA or rate-limit indicators.
- Missing `/.well-known/security.txt` as an informational disclosure-process signal.
- URL, redirect, return, destination, or callback field names as a passive SSRF/open-redirect surface signal.

### A05:2021 - Security Misconfiguration

Checks include:

- Missing security headers.
- Directory listings.
- Possible exposed `.git` content.
- Verbose error or stack-trace markers.
- Technology and server banners.

### A06:2021 - Vulnerable and Outdated Components

The scanner looks for version-like references for common frontend components and framework names. This is fingerprinting, not a definitive vulnerability database match. A real version assessment should compare detected versions against a maintained CVE database.

### A07:2021 - Identification and Authentication Failures

Heuristics include login-like forms missing an obvious CSRF token and session cookies that appear to lack HttpOnly protection. These are signals requiring manual review, not proof of an authentication flaw.

### A08:2021 - Software and Data Integrity Failures

The scanner checks for external JavaScript/CSS assets without SRI and external script references using insecure or protocol-relative transport. Non-asset navigation links and language paths are excluded to reduce false positives.

### A09:2021 - Security Logging and Monitoring Failures

Weak passive signals include server errors or verbose error pages without visible request, correlation, incident, or trace identifiers. Logging cannot be fully assessed from an unauthenticated page scan.

### A10:2021 - Server-Side Request Forgery

The scanner identifies URL-consuming field names such as `url`, `redirect`, `return`, `next`, `destination`, and `callback`. It does not send requests to internal addresses or cloud metadata endpoints, so it cannot prove SSRF.

## 6. Risk Engine

Each technical finding has a base severity from 1 to 4. The risk engine multiplies it by fixed business-context factors:

- Customer data: `True = 1.6`, `False = 1.0`
- Internet-facing: `True = 1.4`, `False = 1.0`
- Environment: production `1.5`, staging `1.1`, development `0.7`
- Criticality: low `0.8`, medium `1.1`, high `1.5`

The result is normalized to a 0-10 score and classified as:

- Critical: 8.0 or higher
- High: 6.0 or higher
- Medium: 3.5 or higher
- Low: below 3.5

The current simplified URL-only interface uses a fixed internal context of production, internet-facing, customer-data handling, and medium criticality. This keeps the workflow simple while preserving the existing scoring model.

## 7. False-Positive Controls

The scanner includes several safeguards:

- Generic response similarity filtering for sensitive-path checks.
- Login-page recognition for normal public admin login pages.
- Path-specific content indicators for `.env`, `config.php`, `.git`, actuator, server status, and phpinfo checks.
- Deduplication of external asset integrity findings into one summary finding.
- Ignoring external navigation and language links that are not JS/CSS assets.
- Findings describe heuristics as possible indicators rather than confirmed vulnerabilities.

A scanner cannot guarantee zero false positives or zero false negatives. Final validation requires source review, authenticated testing, configuration review, and human analysis.

## 8. What the Tool Does Not Do

VulnSense does not perform:

- 50 SQL injection payloads.
- 100 XSS payloads.
- Automated exploitation.
- Brute-force authentication testing.
- Credential attacks.
- Destructive requests.
- Internal network or cloud metadata probing.
- Full authenticated access-control testing.
- Complete CVE matching without a vulnerability intelligence database.

Large payload lists and automated exploit attempts would violate the tool's passive/read-only design and create unnecessary risk. The scanner uses limited harmless detection markers instead.

## 9. PDF Report

The PDF contains:

- Target and assessment context.
- Risk-level summary.
- OWASP category summary.
- Detailed finding tables.
- Base severity and contextual score.
- Plain-English risk justification.
- Description and remediation recommendation.
- Authorized-use disclaimer.

## 10. Validation Performed

The project has been validated with:

- Python byte compilation of all modules.
- Import tests for `core`, `gui`, scanner, risk engine, report generator, and Flask app.
- Flask homepage route test.
- Target-URL-only `/scan` route test.
- PDF export route test.
- Scanner smoke test against a reachable public target.

## 11. Recommended Production Improvements

For a stronger commercial-grade assessment platform, the next upgrades would be:

1. Add a maintained CVE/component intelligence feed.
2. Add optional authenticated scan profiles with encrypted credential storage.
3. Add a crawl budget and same-origin link discovery.
4. Add a review workflow for confirming or dismissing findings.
5. Add scan history and persistent storage.
6. Add rate limiting and per-target request budgets.
7. Add tests using controlled local fixtures for reflected XSS and SQL error detection.
8. Add a configurable allowlist for authorized target domains.
9. Add secure production deployment with authentication, HTTPS, and a WSGI server.

## 12. Detailed 200-Line Description

1. VulnSense is a browser-based web vulnerability assessment application.
2. The application uses Flask to provide its web interface.
3. The scanner is written in portable Python.
4. The project runs from a Python virtual environment.
5. The main entry point is `main.py`.
6. Running `main.py` starts the Flask development server.
7. The default server address is `127.0.0.1`.
8. The default server port is `5050`.
9. Users open the dashboard in a normal web browser.
10. The dashboard accepts a target URL as its main input.
11. The target URL may use HTTP or HTTPS.
12. The scanner normalizes URLs before making requests.
13. A missing scheme is treated as HTTP.
14. An empty URL is rejected safely.
15. Network failures become scan reliability findings.
16. A failed check does not stop every other check.
17. The scanner uses the Requests library for web requests.
18. Requests use a defined timeout.
19. Requests use a VulnSense user-agent string.
20. Certificate verification is disabled for assessment visibility.
21. Certificate verification is disabled only for scanner requests.
22. TLS socket checks use Python standard libraries.
23. Optional certificate parsing uses pyOpenSSL.
24. Missing optional certificate support fails silently.
25. The scanner does not submit credentials automatically.
26. The scanner does not perform brute-force authentication.
27. The scanner does not upload files.
28. The scanner does not modify target data.
29. The scanner does not send destructive commands.
30. The scanner is intended for authorized assessments.
31. Findings are represented by a dataclass.
32. Every finding has a stable finding identifier.
33. Every finding has a human-readable title.
34. Every finding has an internal category.
35. Every finding has an OWASP category.
36. Every finding has a base severity from one to four.
37. Every finding has a technical description.
38. Every finding has a remediation recommendation.
39. Base severity represents technical concern.
40. Contextual risk is calculated separately.
41. Security headers are checked first.
42. Missing HSTS is mapped to A05.
43. Missing CSP is mapped to A05.
44. Missing X-Frame-Options is mapped to A05.
45. Missing X-Content-Type-Options is mapped to A05.
46. Missing Referrer-Policy is mapped to A05.
47. Missing Permissions-Policy is mapped to A05.
48. Header findings explain their security purpose.
49. Header findings provide configuration guidance.
50. Header checks inspect the initial response.
51. Plain HTTP is reported as a cryptographic concern.
52. Plain HTTP receives severity four.
53. TLS protocol negotiation is inspected where possible.
54. SSLv3 is treated as obsolete.
55. TLS 1.0 is treated as obsolete.
56. TLS 1.1 is treated as obsolete.
57. Weak protocol findings map to A02.
58. Certificate expiry is checked when available.
59. Expiring certificates receive a warning severity.
60. Expired certificates receive a warning severity.
61. HTTPS forms are inspected for HTTP actions.
62. HTTP form actions can expose submitted data.
63. Insecure form submission maps to A02.
64. Password input autocomplete is inspected.
65. Missing restrictive autocomplete is informational.
66. Cookies are inspected from Set-Cookie headers.
67. Secure cookie flags are checked.
68. HttpOnly cookie flags are checked.
69. SameSite cookie flags are checked.
70. Cookie weaknesses map to A02.
71. Server banner disclosure is checked.
72. X-Powered-By disclosure is checked.
73. ASP.NET version disclosure is checked.
74. Banner findings map to A05.
75. Directory listing paths are tested conservatively.
76. Upload directories are inspected.
77. Image directories are inspected.
78. Asset directories are inspected.
79. Backup directories are inspected.
80. Git directories are inspected.
81. Directory listing markers are matched in responses.
82. Exposed Git content receives higher severity.
83. Random missing paths are requested.
84. Verbose debug markers are searched for.
85. Stack traces are treated as misconfiguration indicators.
86. Debug output findings map to A05.
87. Access-control testing is deliberately heuristic.
88. Common sensitive paths are requested without credentials.
89. HTTP 200 alone is not enough for a finding.
90. Generic page similarity is used to reduce noise.
91. Normal admin login pages are filtered.
92. Path-specific content hints are required.
93. Environment files require environment-like content.
94. Configuration files require configuration-like content.
95. Actuator responses require structured indicators.
96. PHP information pages require PHP indicators.
97. Server-status pages require status indicators.
98. Access-control findings map to A01.
99. The access-control check is not authorization proof.
100. Authenticated role testing requires application-specific sessions.
101. Injection checks begin with discovered parameters.
102. URL query parameters are parsed safely.
103. GET form fields are discovered from HTML.
104. POST fields are not automatically submitted.
105. A harmless reflection marker is used for XSS detection.
106. The marker is `<vulnsense_test>123</vulnsense_test>`.
107. One reflection request is made per parameter.
108. The response is checked for exact marker reflection.
109. Exact unescaped reflection is a possible XSS signal.
110. Reflection findings map to A03.
111. Reflection findings do not execute JavaScript.
112. Reflection findings do not prove browser exploitability.
113. Stored XSS requires repeated application-state testing.
114. DOM XSS requires JavaScript analysis.
115. Authenticated XSS requires credentials and sessions.
116. SQL error detection uses a single quote probe.
117. One SQL probe is made per discovered parameter.
118. The probe is URL-encoded by Requests.
119. Database error text is searched in the response.
120. SQL syntax messages are recognized.
121. MySQL fetch errors are recognized.
122. Oracle quotation errors are recognized.
123. Unclosed quotation errors are recognized.
124. SQLSTATE indicators are recognized.
125. SQL error findings receive severity four.
126. SQL findings map to A03.
127. SQL error text is not proof of exploitability.
128. Blind SQL injection may remain undetected.
129. Time-based SQL testing is intentionally omitted.
130. UNION-based SQL testing is intentionally omitted.
131. Insecure design checks use page-level signals.
132. Login-like forms are identified heuristically.
133. HTTP login forms receive a warning signal.
134. CAPTCHA text is recognized as an anti-automation signal.
135. Rate-limit text is recognized as an anti-automation signal.
136. Missing security.txt is informational.
137. security.txt supports vulnerability disclosure processes.
138. URL-like field names are identified passively.
139. Redirect fields may indicate review surfaces.
140. Callback fields may indicate review surfaces.
141. SSRF is not actively tested.
142. Internal addresses are never requested automatically.
143. Cloud metadata addresses are never requested automatically.
144. URL-surface findings map to A10.
145. Component checks inspect visible version signals.
146. Common frontend library names are recognized.
147. Common framework version patterns are recognized.
148. Version detection is fingerprinting only.
149. Version detection is not CVE confirmation.
150. A maintained vulnerability database is needed for CVE matching.
151. Integrity checks inspect external script references.
152. Integrity checks inspect external stylesheet references.
153. Non-asset navigation links are ignored.
154. Language links are ignored.
155. JavaScript assets are identified by path patterns.
156. CSS assets are identified by path patterns.
157. Missing SRI is grouped into one finding.
158. Grouping prevents duplicate report noise.
159. Insecure external script transport is a separate concern.
160. Integrity findings map to A08.
161. Authentication heuristics inspect login-like forms.
162. POST login forms are checked for token indicators.
163. Missing obvious CSRF tokens are heuristic findings.
164. Session cookies are inspected for HttpOnly.
165. Authentication findings map to A07.
166. Logging heuristics inspect error responses.
167. Server errors are checked for tracking cues.
168. Correlation identifiers are recognized.
169. Request identifiers are recognized.
170. Verbose error output receives monitoring context.
171. Logging findings map to A09.
172. Logging cannot be fully assessed externally.
173. The risk engine receives all findings.
174. A business context dataclass stores scoring context.
175. The simplified UI uses a fixed internal context.
176. Customer data handling affects impact.
177. Internet exposure affects likelihood.
178. Production deployment increases risk.
179. Medium criticality provides a moderate multiplier.
180. Findings are normalized to a ten-point scale.
181. Critical findings score at least eight.
182. High findings score at least six.
183. Medium findings score at least three point five.
184. Remaining findings are Low.
185. Findings are sorted by contextual score.
186. Justifications explain context influence.
187. The Flask page displays risk summary cards.
188. The results table displays finding titles.
189. The results table displays technical categories.
190. The results table displays OWASP categories.
191. The results table displays contextual scores.
192. Finding details expand inside the browser page.
193. Recommendations are shown with each finding.
194. PDF export uses ReportLab.
195. The PDF includes risk totals.
196. The PDF includes OWASP totals.
197. The PDF includes detailed finding tables.
198. The PDF includes an authorized-use disclaimer.
199. Human review remains necessary for final conclusions.
200. VulnSense is a safe assessment aid, not an exploit framework.
