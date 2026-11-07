Lynceus

Continuous Phishing Detection & Intelligence Engine

Project Type: Endpoint Security / Email Security / Threat Intelligence
Status: Active Development
Architecture: Local-first, event-driven, modular
Primary Platform: Windows
Browser Support: Chrome / Microsoft Edge
Email Support: Gmail / Microsoft Outlook
Backend: Python / FastAPI
Windows Agent: C# / .NET
Frontend: React / TypeScript

⸻

1. Project Overview

Lynceus is a continuously operating phishing detection and threat intelligence system designed to identify malicious URLs, deceptive hyperlinks, suspicious emails, malicious attachments, QR-code phishing and other phishing-related threats.

Lynceus is NOT a traditional antivirus, a simple URL scanner, or a dashboard that requires users to manually submit suspicious links.

Its primary objective is to detect phishing attempts across multiple digital environments before users interact with malicious content.

The system operates through multiple independent monitoring components:

* Windows background monitoring agent.
* Browser security extension.
* Gmail integration.
* Microsoft Outlook integration.
* Download and file monitoring.
* Deep email and attachment inspection.
* Threat intelligence integrations.
* Automated detection and response engine.

Lynceus must continue operating when its desktop interface is closed.

The desktop interface is a management and investigation component, not the monitoring engine itself.

2. Core Objectives

The system must:

1. Continuously monitor supported digital environments.
2. Detect suspicious and malicious URLs.
3. Identify hidden hyperlinks inside emails and documents.
4. Detect mismatches between displayed link text and actual destinations.
5. Inspect PDF, HTML, image and supported archive attachments.
6. Extract QR codes and URLs from images.
7. Perform OCR-based phishing content analysis.
8. Analyze email headers and authentication results.
9. Identify suspicious redirects and domain impersonation.
10. Integrate with external threat intelligence providers.
11. Correlate multiple independent detection signals.
12. Produce explainable security verdicts.
13. Automatically warn users about confirmed threats.
14. Support reversible quarantine and blocking actions.
15. Maintain forensic evidence and audit records.
16. Protect private user content through local-first processing.

3. Core Architecture

Lynceus consists of three primary architectural layers.

3.1 Sensor Layer

Responsible for collecting security-relevant events.

Components:

* Windows background agent.
* Browser extension.
* Gmail connector.
* Microsoft Graph connector.
* Download monitoring.
* Local file monitoring.

3.2 Intelligence Layer

Responsible for analyzing collected content.

Components:

* Event ingestion.
* MIME email parser.
* HTML analyzer.
* URL extraction and normalization.
* PDF analyzer.
* Image analyzer.
* OCR and QR extraction.
* Archive inspection.
* Domain intelligence.
* Threat intelligence providers.
* Detection correlation engine.
* Explainable risk engine.

3.3 Response Layer

Responsible for protective actions.

Components:

* Desktop notifications.
* Browser blocking.
* Warning interstitials.
* File quarantine.
* Email quarantine through authorized integrations.
* Audit logging.
* Evidence preservation.
* False-positive recovery.

4. Technology Stack

Use the following technology stack unless a documented technical limitation justifies a change.

Component	Technology
Windows agent	C# / .NET Worker Service
Desktop application	Tauri + React
Frontend	React + TypeScript
Browser extension	TypeScript / Chrome Manifest V3
Backend	Python / FastAPI
Database	PostgreSQL
Task queue	Redis
Email parsing	Python email
HTML parsing	BeautifulSoup
PDF analysis	PyMuPDF / pikepdf
OCR	Tesseract
Image processing	OpenCV
QR extraction	pyzbar
Threat intelligence	Provider adapters
Containers	Docker
Testing	Pytest / xUnit
API documentation	OpenAPI

Prefer a modular monolith initially. Do not introduce unnecessary microservices.

5. Threat Intelligence Integrations

Create a provider abstraction layer.

Initial integrations:

* urlscan.io
* VirusTotal
* Google Safe Browsing or Google Web Risk, according to intended use.
* OpenPhish.
* PhishTank.
* RDAP.

Requirements:

* Asynchronous requests.
* Provider-specific timeouts.
* Rate-limit handling.
* Circuit breakers.
* Response caching.
* Provider health monitoring.
* Source timestamps.
* Provider provenance.
* Graceful degradation.

Never make Lynceus dependent on a single provider.

Never assume a provider timeout means a URL is safe.

Never submit private URLs, authentication tokens, complete emails or confidential attachments to external services without explicit authorization.

Use private urlscan submissions when appropriate, but remember that private scanning still involves sending data to an external provider.

6. Detection Engine

Build deterministic detection before introducing AI-assisted analysis.

Supported detection categories:

URL Detection

* IP-based URLs.
* Punycode and IDN homographs.
* Suspicious subdomains.
* Lookalike domains.
* URL shorteners.
* Encoded redirects.
* Suspicious URL parameters.
* Credential-harvesting patterns.
* Redirect chains.
* Domain reputation.

Email Detection

* Sender and Reply-To mismatch.
* SPF failures.
* DKIM verification failures.
* DMARC failures.
* Suspicious email routing.
* Hidden hyperlinks.
* Displayed URL versus actual destination mismatch.
* Suspicious image hyperlinks.
* Suspicious MIME structures.
* Social-engineering indicators.

Attachment Detection

* PDF URI annotations.
* Embedded files.
* PDF JavaScript actions.
* HTML redirects.
* Suspicious forms.
* QR-code phishing.
* OCR-extracted URLs.
* Nested archives.
* HTML smuggling indicators.

Detection results must include supporting evidence.

Do not classify files as malicious merely because they contain a particular feature.

7. Verdict Model

Implement these verdict states:

* MALICIOUS
* SUSPICIOUS
* BENIGN
* UNKNOWN
* ERROR

UNKNOWN must never be treated as BENIGN.

Every verdict must include:

* Risk score.
* Confidence category.
* Detection signals.
* Evidence references.
* Provider results.
* Timestamp.
* Recommended response.
* Applied response.

Risk scoring must be explainable and configurable.

Do not use an LLM as the sole decision-maker for maliciousness.

AI may assist with explanation, content interpretation and threat report summarization, but deterministic rules and validated intelligence must remain the foundation.

8. Automatic Response

Implement a policy-driven response engine.

Low Risk

* Record event.
* Continue monitoring.

Suspicious

* Notify user.
* Display warning.
* Preserve evidence.

High Risk

* Display browser warning.
* Isolate suspicious downloaded files.
* Request confirmation before destructive actions.

Confirmed Malicious

* Block browser navigation.
* Quarantine supported files.
* Apply authorized email quarantine actions.
* Record evidence.
* Notify user.

All response operations must be:

* Reversible where technically possible.
* Idempotent.
* Auditable.
* Permission-controlled.
* Fail-safe.

Never automatically delete user files or emails.

9. Privacy and Security Requirements

Privacy is a fundamental architectural requirement.

Mandatory controls:

* Local-first content inspection.
* OAuth least-privilege permissions.
* Encrypted credential storage.
* Encrypted evidence storage.
* No secrets in logs.
* No unnecessary external submissions.
* Configurable retention.
* User-controlled deletion.
* Audit logging.
* Authenticated local IPC.
* Strict API authentication.
* Secure webhook validation.
* SSRF protection.
* Rate limiting.
* Parser isolation.
* Archive extraction limits.
* Sandbox network restrictions.

All suspicious documents must be treated as untrusted input.

Never execute document scripts or embedded content directly on the host.

Do not allow URL scanning to access internal networks, loopback interfaces, private addresses, link-local services or cloud metadata endpoints.

Revalidate all redirect destinations and resolved IP addresses.

10. Browser Security

Implement a Chrome Manifest V3 extension compatible with Microsoft Edge.

Required functionality:

* Navigation monitoring.
* URL inspection.
* Redirect monitoring.
* Suspicious-link detection.
* Download URL monitoring.
* Local verdict caching.
* Communication with the Windows agent.
* Warning interstitial.
* Authorized override.
* Minimal browser permissions.

The extension must not indefinitely delay navigation while external providers are queried.

Use local cached verdicts and bounded asynchronous analysis.

11. Email Security

Gmail

Use Gmail API and OAuth.

Implement:

* Gmail watch subscriptions.
* Google Cloud Pub/Sub notifications.
* Message retrieval.
* MIME parsing.
* Attachment extraction.
* Hidden-link inspection.
* Message-to-verdict correlation.
* Watch renewal.
* History synchronization and recovery.

Outlook

Use Microsoft Graph.

Implement:

* OAuth authentication.
* Message change subscriptions.
* Webhook validation.
* Message retrieval.
* Attachment extraction.
* MIME and HTML inspection.
* Subscription renewal.
* Missed-event recovery.

Start with read-only permissions.

Message modification and quarantine permissions must be separate, explicitly authorized capabilities.

Do not claim to monitor every mailbox automatically. Only monitor mailboxes and folders supported by the granted permissions and configured subscriptions.

12. Windows Background Agent

Develop a C#/.NET Worker Service.

Responsibilities:

* Run independently of the desktop UI.
* Monitor configured download directories.
* Detect new files.
* Calculate SHA-256 hashes.
* Identify file types through file signatures.
* Correlate browser downloads where possible.
* Submit files for analysis.
* Receive verdicts.
* Execute authorized response actions.
* Display Windows notifications.
* Maintain a local event queue during connectivity failures.

Use reliable file-event processing, debounce, retry and stable-file checks.

Avoid duplicate scans.

13. Database

Use PostgreSQL.

Initial entities:

* users
* devices
* integrations
* events
* artifacts
* extracted_urls
* domains
* provider_results
* detections
* verdicts
* evidence
* response_actions
* audit_logs
* allowlist
* blocklist

Use UUID identifiers.

Separate sensitive evidence from normal metadata.

Store hashes and references instead of duplicating raw email content unnecessarily.

Implement database migrations and indexes from the beginning.

14. Repository Structure

Use a monorepo:

Lynceus/
├── apps/
│   ├── desktop/
│   ├── browser-extension/
│   └── admin-console/
│
├── agents/
│   └── windows-agent/
│
├── services/
│   ├── api-gateway/
│   ├── ingestion/
│   ├── email-analysis/
│   ├── document-analysis/
│   ├── url-analysis/
│   ├── domain-intelligence/
│   ├── reputation/
│   ├── detection-engine/
│   ├── risk-engine/
│   └── response-engine/
│
├── integrations/
│   ├── gmail/
│   ├── microsoft-graph/
│   ├── urlscan/
│   ├── virustotal/
│   ├── google-safe-browsing/
│   ├── openphish/
│   └── phishtank/
│
├── shared/
│   ├── contracts/
│   ├── schemas/
│   ├── crypto/
│   └── logging/
│
├── rules/
│   ├── url/
│   ├── email/
│   ├── document/
│   ├── identity/
│   └── correlation/
│
├── infrastructure/
│   ├── docker/
│   ├── postgres/
│   ├── redis/
│   └── monitoring/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── adversarial/
│   └── regression/
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   ├── PRIVACY.md
│   ├── DETECTION_ENGINE.md
│   ├── THREAT_MODEL.md
│   └── API_CONTRACTS.md
│
├── docker-compose.yml
├── .env.example
├── CLAUDE.md
└── README.md

The actual implementation may adjust this structure when justified by engineering requirements.

15. Development Roadmap

Build Lynceus in controlled phases.

Phase 1 — Foundation

* Repository setup.
* Backend skeleton.
* Database.
* Redis.
* Event contracts.
* URL normalization.
* Initial detection rules.
* API tests.

Acceptance criteria: A functioning local URL analysis engine with reproducible results.

Phase 2 — Deep Content Inspection

* MIME parser.
* HTML parser.
* Hidden-link detection.
* PDF inspection.
* Image processing.
* QR extraction.
* OCR.
* Archive inspection.

Acceptance criteria: Lynceus can extract suspicious indicators from representative EML, HTML, PDF and image samples.

Phase 3 — Threat Intelligence

* Provider abstraction.
* urlscan.
* VirusTotal.
* Safe Browsing / Web Risk.
* OpenPhish.
* PhishTank.
* Caching and rate limiting.

Acceptance criteria: Independent provider failures do not break the local analysis pipeline.

Phase 4 — Continuous Monitoring

* Windows agent.
* Filesystem monitoring.
* Browser extension.
* Native Messaging.
* Download inspection.
* Desktop notifications.

Acceptance criteria: Monitoring works independently of the desktop UI.

Phase 5 — Email Integrations

* Gmail OAuth and watch.
* Outlook OAuth and Graph subscriptions.
* Message retrieval.
* Attachment processing.
* Event recovery.

Acceptance criteria: Authorized test mailboxes can be monitored and incoming messages analyzed automatically.

Phase 6 — Automated Response

* Browser blocking.
* File quarantine.
* Email quarantine.
* Audit records.
* False-positive recovery.

Acceptance criteria: Authorized response actions are reversible, idempotent and auditable.

Phase 7 — Production Hardening

* Security review.
* Threat modeling.
* Adversarial tests.
* Performance tests.
* Privacy review.
* Installation and upgrade process.
* Documentation.

Acceptance criteria: Reproducible deployment, verified security controls and documented limitations.

16. Testing Requirements

Never consider a detection feature complete without testing.

Build a labelled test corpus containing:

* Benign emails.
* Phishing emails.
* Hidden hyperlink mismatches.
* Suspicious PDFs.
* PDFs containing QR codes.
* QR phishing images.
* HTML redirect samples.
* URL shorteners.
* Punycode domains.
* Benign lookalike examples.
* Nested archive samples.
* Malformed MIME messages.
* ZIP bomb test fixtures.
* SSRF test URLs.
* False-positive scenarios.

Use synthetic test samples and authorized phishing datasets.

Do not test against real third-party victims.

Track:

* True positives.
* False positives.
* False negatives.
* Precision.
* Recall.
* F1 score.
* Processing latency.
* Provider availability.
* Duplicate event rate.
* Quarantine recovery success.

A detection engine must be evaluated against labelled samples, not just successful demonstrations.

17. Claude Code Engineering Instructions

Claude Code must follow these rules throughout development.

1. Read README.md and CLAUDE.md before modifying the repository.
2. Understand the existing architecture before introducing new components.
3. Do not generate the entire application in one operation.
4. Implement one milestone at a time.
5. Write tests alongside every major feature.
6. Do not invent API capabilities.
7. Verify third-party API documentation before implementing integrations.
8. Never hardcode credentials, tokens or API keys.
9. Never place secrets in source control.
10. Never bypass privacy requirements to simplify development.
11. Never execute suspicious files on the host.
12. Do not use real malicious URLs for uncontrolled testing.
13. Use mock providers for development and integration testing.
14. Document every important architectural decision.
15. Prefer maintainable and testable code over unnecessary complexity.
16. Do not introduce dependencies without explaining their purpose.
17. Do not claim a feature works without an executable test or verified integration.
18. Do not mark a milestone complete while acceptance criteria remain unmet.

Before each milestone:

* Explain the implementation plan.
* Identify affected modules.
* Identify security implications.
* Define acceptance criteria.

After each milestone:

* Run tests.
* Report failures.
* Document completed functionality.
* Document known limitations.
* Identify the next milestone.

18. Definition of Success

Lynceus will be considered a successful first major release when it can:

1. Run as a Windows background monitoring service.
2. Monitor supported browser activity.
3. Detect suspicious downloaded files.
4. Connect to authorized Gmail and Outlook mailboxes.
5. Extract hidden hyperlinks from emails.
6. Analyze PDF attachments.
7. Extract QR codes from images.
8. Detect phishing indicators using multiple independent signals.
9. Correlate external threat intelligence.
10. Produce evidence-backed verdicts.
11. Notify users automatically.
12. Block confirmed malicious browser navigation.
13. Quarantine supported malicious files safely.
14. Preserve forensic evidence.
15. Recover from false positives.
16. Continue operating without the dashboard open.
17. Protect private content by default.

⸻

Final Engineering Principle

Lynceus must be a genuine security engineering system.

Do not prioritize visual appearance over detection accuracy.

Do not prioritize AI features over deterministic analysis.

Do not prioritize automation over safety.

Do not confuse a successful API response with a successful threat detection.

The central mission is:

Detect phishing before interaction. Investigate the evidence. Protect the user. Explain every decision.