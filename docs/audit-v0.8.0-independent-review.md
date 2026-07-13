# RightOut v0.8.0 — Unabhängiges Release-/Security-/Privacy-Audit

**Prüfumgebung:** frischer Clone, Branch-HEAD `704b020` (= Tag `v0.8.0`), Node 22.22, Python 3.11, sauberes `npm ci --ignore-scripts`. Alle Aussagen unten sind gegen Code, veröffentlichtes TGZ, Manifeste und Katalogdateien belegt. Es wurde nichts verändert und kein realer Provider-/E-Mail-/Formular-Write ausgelöst.

## Urteil: **NO-GO für v0.8.0 wie ausgelobt** — herabstufbar auf **GO WITH CONDITIONS** nach genau einem Fix

Der assistierte, approval-gated Kern (manueller Scan + freigabegebundene Removals) ist solide gebaut und wäre freigabefähig. Aber die **Kern-Auslobung „bounded autonomous … campaigns" / „drains 59 combined catalog lanes in bounded four-route campaign batches" / „One scan-only campaign can drain all 59 lanes" ist im veröffentlichten Paket nicht funktionsfähig**: eine autonome Kampagne kann ihre Discovery nie persistieren und läuft in eine Endlosschleife. Das ist ein echter Blocker (P1), aber ein billig behebbarer (Einzeiler + echter E2E-Test). Solange das nicht gefixt oder die Autonomie-/„59-Lanes"-Auslobung zurückgenommen ist, ist die Release-Aussage widerlegt.

---

## A. Executive Summary (max. 10 Punkte)

1. **P1 – Autonomer globaler Live-Scan ist kaputt (silent fail).** `runLiveScan` setzt bei Kampagnen `mode:"campaign_gated_live_scan"`; `caseLedger.recordScan` akzeptiert aber **nur** `"approval_gated_live_scan"` und wirft sonst `invalid_scan_report`. Empirisch bestätigt. Folge: Kampagnen-Scans persistieren nie → Fall bleibt `new` → `planGlobalScanCampaignNext`/`planParityCampaignNext` re-emittieren denselben Scan-Batch endlos, `done_for_now` wird nie erreicht.
2. **Der grüne Test beweist hier nichts.** Der „Full-Autonomy"-Test seedet den Ledger vorab mit einem `approval_gated_live_scan`-Report und fährt die Kampagne mit `effects:["submit_email","submit_form"]`; der Planner-Test **injiziert** aufgelöste Fallzustände von Hand. Der reale Pfad Kampagne→`rightout_live_scan(campaignId)`→`recordScan`→Status-Fortschritt wird nirgends durchlaufen.
3. **„59 Scan-Lanes" ist überzogen.** Code-erzwungen scanbar sind exakt **21** Lanes (alle US-`people_search`). Die „59 (30 people-search + 29 controller/B2B)" sind eine Katalog-Domain-Zählung; 38 davon sind `human_only` oder nicht `scan.supported` und werden von `runLiveScan` mit `unsupported_broker` abgelehnt. Es gibt nur 22 `people_search`-Einträge — die Zahl „30 people-search" ist zusätzlich nicht nachvollziehbar.
4. **„DE/EU live scan" = technische Länderunterstützung, nicht reale Discovery.** Ländercodes werden korrekt ISO-validiert, Groß/Klein normalisiert, ungültige fail-closed (`unsupported_country`), Nicht-Brave-Länder → expliziter `ALL`/`worldwide_fallback`. Aber alle 21 Scan-Broker sind US-People-Search; ein EU-Subjekt erzeugt `site:beenverified.com "Name"`-Queries, die realistisch leer sind. EU-Adtech-Controller sind identifier-basiert und gar nicht scan-fähig.
5. **Release-/Supply-Chain: sauber und reproduzierbar.** TGZ-SHA256 = `d2fdc365…` stimmt mit `RELEASE-SHA256SUMS`, Release-Asset-`digest` und lokal berechnetem Hash überein. `dist/index.js` + alle 21 `dist/lib/*.mjs` **reproduzieren byte-genau** aus der Quelle. Paket-Inhalt = Working-Tree. `npm-shrinkwrap.json` ≡ `package-lock.json`. SBOM: 47 Pakete = 47 Non-Dev-Lockfile-Einträge. `npm audit --omit=dev --audit-level=high`: 0.
6. **Approval-/Fail-closed-Modell: stark.** Jeder Effekt bindet via `beforeToolCall` einen deterministischen `scopeBinding(input, attestations, …)` an die host-autoritative `toolCallId` (TTL 120 s), der bei Ausführung aus den echten Params **neu berechnet und verglichen** wird (`approval.binding !== scanScopeBinding(...)` → `throw`), single-use (`delete` nach `get`). Das schließt TOCTOU/Param-Swap und Approval-Replay. Kampagnen-Grants binden Profil-, Katalog- und Runtime-Scope-Digest.
7. **SSRF/Netz: an OpenClaw-SDK delegiert, korrekt eingesetzt.** Alle Netzcalls laufen über `fetchWithSsrFGuard` mit `requireHttps:true`, Hostname-Allowlist, `maxRedirects:0`/`redirect:"manual"`, Timeout. Brave-URL ist Konstante; Kandidaten-URLs werden validiert (https, kein user/pass, Host-Allowlist) und laut Invarianten nie persistiert/zurückgegeben/gefetcht.
8. **SMTP: gehärtet, kein Header-Injection-Vektor.** Empfänger stammt fix aus dem Katalog (`rescue_email`, gegen `official_domains` geprüft), Betreff/`from` fix; PII geht nur in den Body, nie in Header. `rejectUnauthorized:true`, `minVersion:TLSv1.2`, `requireTLS`. `abort`-Handling schließt Transport.
9. **State-Machine schützt terminale Zustände korrekt.** `transition()` erzwingt die Übergangstabelle; `partially_removed`/`request_rejected`/`identity_verification_required` können von einem Scan **nicht** überschrieben werden (Übergang illegal → `throw`). Nebenwirkung: ein Scan-Batch, der einen solchen Broker enthält, lässt `recordScan` komplett fehlschlagen (`durable_case_recorded:false`) und verwirft still auch die anderen Beobachtungen des Batches (P3).
10. **Parity-Ehrlichkeit: gut belegt.** Provider-Terms: 22 Einträge = **8 `explicit_automation_prohibition` + 14 `needs_evidence` + 0 Erlaubnisse** (exakt wie ausgelobt). Parity: 22 Broker = 20 `web_form` + 1 `email` + 1 `phone` (Spokeo Human-Gate). `release_check.py`: ok. Coverage 94,2 % Lines / 81,1 % Branch / 87,3 % Funcs; 282 Tests pass/1 skip; Python 50 OK.

---

## B. Release Blockers (nur echte)

- **BL-1 (P1):** Autonome Kampagnen-Discovery persistiert nicht → Autonomie-Loop terminiert nie. Blockiert die Auslobungen „autonomer Betrieb", „globaler autonomer Scan", „59 Lanes drainbar". *Entweder fixen oder diese Auslobungen aus Release Notes/README streichen.*

Kein weiterer P0/P1 gefunden. Ich sage das ausdrücklich: Supply-Chain, Approval-Bindung, SSRF, SMTP-TLS und Fail-closed-Writes sind belegbar in Ordnung — hier wurden **keine** Blocker erfunden.

---

## C. Findings-Tabelle

| ID | Sev | Bereich | Finding | Evidenz | Reproduktion | Auswirkung | Konkreter Fix | Regressionstest |
|----|-----|---------|---------|---------|--------------|------------|---------------|-----------------|
| F-1 | **P1** | Autonomie/Live-Scan | Kampagnen-Scan-Reports (`mode:"campaign_gated_live_scan"`) werden von `recordScan` verworfen; Discovery persistiert nie | `lib/live-scan.mjs:633` setzt Kampagnenmodus; `lib/cases.mjs:257` verlangt `mode==="approval_gated_live_scan"`; `index.ts:2657` ruft `recordScan` unverändert; empirischer Test: `campaign_gated_live_scan => THREW: invalid_scan_report` | discover-only Kampagne (`effects:["discover"]`) starten → `rightout_campaign_next` → `rightout_live_scan(campaignId)` → `durable_case_recorded:false` → nächster `campaign_next` liefert denselben Batch | Headline-Autonomiefeature nicht nutzbar; Endlos-Loop, kein Fortschritt zu Removal; Kampagnen funktionieren nur, wenn zuvor assistiert (non-campaign) gescannt wurde — Widerspruch zu „autonom" | `recordScan` beide Modi akzeptieren: `!["approval_gated_live_scan","campaign_gated_live_scan"].includes(report.mode)`; alternativ Mode in `index.ts` vor `recordScan` normalisieren | E2E: echte discover-only-Kampagne über `campaign_next`→`live_scan`(campaignId, gemockter Brave-Fetch)→assert `durable_case_recorded===true` und 2. `campaign_next` liefert Fortschritt/`done_for_now` |
| F-2 | **P2** | Claim/Doku | „59 combined scan lanes / 30 people-search" überzeichnet die code-erzwungene Scan-Menge (21, alle US people-search) | `runLiveScan` (`lib/live-scan.mjs:570-577`) + `planGlobalScanCampaignNext` (`lib/parity-autopilot.mjs:46-51`): Gate = `category∈{people_search,data_broker} ∧ scan.supported ∧ policy=search_index_only`; berechnet = 21; `core.json` hat 22 people_search; README:79/94, `docs/broker-coverage.md:37` | Katalog zählen: `scan.supported===true` ⇒ 21; „30 people-search" nicht reproduzierbar | Nutzer/Auditor erwarten 59 scanbare Lanes; real 21 erreichbar | README/Release-Notes: „21 code-durchsetzbare Brave-Scan-Lanes; 59 = Katalog-Domains, davon 38 human_only/nicht scan.supported" | Test, der „scan-durchsetzbare Lane-Anzahl" gegen die Doku-Zahl asserted |
| F-3 | **P2** | Discovery-Realität | „DE/EU/global live scan" ist technische Länderunterstützung, keine reale Broker-Discovery außerhalb der US people-search | `braveLocaleForCountry` (`:537`) akzeptiert alle ISO-Länder; aber alle 21 Scan-Broker `official_domains` sind US people-search; EU-Adtech = `scan.supported:false` | EU-Profil scannen → Queries `site:<us-broker> "Name"` → praktisch `inconclusive` | „Live-Scan für alle Länder" wird als reale Auffindbarkeit missverstanden | README bereits teils ehrlich; Coverage-Gap `controller_and_b2b_broker_domains_may_have_no_public_person_profile_surface` prominenter machen; „technische Länderunterstützung ≠ Discovery" explizit | Test mit synthetischem DE/JP/BR-Profil, der `indirect_exposure=0` und korrekten Coverage-Gap-Text asserted |
| F-4 | **P3** | Semantik | Impliziter US-Default bei fehlendem `country` | `lib/live-scan.mjs:159` `profile.country \|\| "US"` (ebenso Adressen `:202`, `:241`) | Profil ohne `country` → Brave-Locale US | EU-Subjekt ohne gesetztes Land wird still US-lokalisiert; widerspricht „keine implizite US-Voreinstellung" | `country` verpflichtend machen oder Default explizit im Report ausweisen | Test: Profil ohne `country` → erwartetes Verhalten dokumentiert/erzwungen |
| F-5 | **P3** | Robustheit | Ein Broker in geschütztem Zustand lässt `recordScan` den **ganzen** Batch verwerfen (still) | `lib/cases.mjs:282` schützt nur `submitted/verification_pending/awaiting_processing/confirmed_removed`; `partially_removed` etc. lösen in `transition` `illegal_case_transition` aus → gesamte `withProfile`-Transaktion scheitert | Scan-Batch mit einem `partially_removed`-Broker → `durable_case_recorded:false` für alle | Frische Beobachtungen anderer Broker gehen still verloren | In `recordScan` geschützte Zustände pro Broker überspringen statt werfen | Test: gemischter Batch, assert dass Nicht-geschützte Broker trotzdem persistieren |
| F-6 | **P3** | Release-Hygiene | GitHub-Release ist `prerelease:false`, Body sagt aber „Status: release candidate; tagged publication gates pending"; annotierter Tag ist **unsigned** | `get_release` body; `get_tag`: `verification.verified:false, reason:"unsigned"` | API-Abfrage | Widersprüchliches Reifesignal; keine kryptografische Tag-Herkunft (Artefakt-Attestierung via `actions/attest` existiert separat) | Tag signieren (oder Sigstore-Tag-Attestierung dokumentieren); Body/Prerelease-Flag konsistent | Release-Check, der Tag-Signatur/Prerelease-Konsistenz prüft |

---

## D. Claims-Matrix

| Claim | Status | Evidenz | Einschränkung |
|-------|--------|---------|---------------|
| Globaler Live-Scan (alle Länder) | **contradicted** (als „reale Discovery") / **evidenced** (als technische Länderunterstützung) | ISO-Set + `braveLocaleForCountry`; aber 21 US-Broker | Nur technische Akzeptanz; reale Auffindbarkeit ≈ US people-search |
| DE/EU-Support | observed | DE/AT/CH/FR/ES/IT/NL/PL/SE/GB in `BRAVE_COUNTRY_TARGETS`; DE→`de` lang | Kein EU-Broker scan-fähig; EU-Removal = Controller-E-Mail-Lanes, nicht Scan |
| 59 Scan-Lanes | **contradicted** | Code erzwingt 21; „59" = Katalog-Domains | 38 human_only/nicht scan.supported |
| Autonomer Betrieb | **contradicted** | F-1: Kampagnen-Scan persistiert nie | Assistierter Betrieb funktioniert; autonome Discovery nicht |
| Fail-closed Writes | evidenced | Approval-Bindung neu berechnet+verglichen, single-use; fehlende Attestierung → `throw`; Kampagnen-Grant bindet Digests | — |
| OpenClaw-Konformität | observed | `definePluginEntry`, `registerTool`, `requireApproval`/`allow-once`, SecretRef-Enforcement (`isSecretRef`), `ssrf-runtime`; SDK-Pin `2026.6.11` | Gegen OpenClaw-Live-Doku nicht gegengeprüft → `needs_evidence` für exakte Feldkonformität |
| 22/22 Unbroker-Contract-Parität | evidenced | `unbroker-parity.json`=22 (20 form/1 email/1 phone); `release_check` `people_search:22` | Contract-/Datenmodell-Parität, nicht Choreografie-/Wirkungsparität (README sagt das selbst) |
| 21/22 scanbare Unbroker-Lanes | evidenced | 21 `scan.supported`, Spokeo Human-Gate | — |
| Release-Artefakt verifiziert | evidenced | SHA256 match; dist reproduziert byte-genau; Paket=Tree; shrinkwrap≡lock; SBOM konsistent | Tag unsigned (F-6) |
| Approval-fähig | evidenced | 16 approval-gated Tools, `allow-once`/`deny`, TTL 120 s | — |
| DSGVO-taugliche technische Posture | observed | SecretRefs, PII-freie Reports (`values_in_report:false`), `validUntil`-Consent ≤365 T, `purge_subject_state`, Redaction | Rechtliche Konformität `needs_evidence`; keine Aussage „DSGVO-konform" ohne Nachweis (Doku hält das ein) |

---

## E. Fallback-Matrix

| Fall | Erwartet | Tatsächlich | Risiko | Recovery |
|------|----------|-------------|--------|----------|
| Brave nicht verfügbar | `inconclusive`, kein Absence-Claim | `provider_unavailable`→`inconclusive`, `not_found=0` hart (`live-scan:455,621,658`) | keins | Rescan später |
| API-Key fehlt | fail-closed | `missing_provider_secret`/`rightout_not_configured` (`:565`,`index:2620`) | keins | Key konfigurieren |
| Rate Limit 429 | Abbruch, kein falsches Ergebnis | `provider_rate_limited`, Vektor-Loop bricht ab (`:452,606`) | keins | Backoff (kein Auto-Retry) |
| Browser-Backend fehlt | Human-Handoff | `resolveBrowserBackend` → human/`unavailable` | keins | Backend bereitstellen |
| Remote-Browser nicht erlaubt | deny | Gate über `browserApprovalRoutingScope`/`assertCampaignPublisherPermissions` | keins | Explizit erlauben |
| SMTP fehlt | kein E-Mail-Write | `emailMode:"unavailable"` (`index:4886`); `rightout_removal_transport_unavailable` | keins | SMTP-SecretRef setzen |
| IMAP fehlt | keine Inbound-Verifikation | `verificationMode:"unavailable"` | keins | IMAP setzen |
| Provider-Formular verändert | deny | ARIA-ref-exakt; fehlende `date_of_birth`-Attest → block (`index:2115-2142`) | keins | Manueller Review |
| CAPTCHA/MFA/OTP | human-only | `challenge_policy`, host-side arithmetic; verzerrter Text/OTP bleiben Mensch | keins | Human-Task |
| Provider-Terms unklar | deny | `needs_evidence`(14) → kein Auto-Run | keins | Written authorization |
| Provider verbietet Automation | deny | `explicit_automation_prohibition`(8) → Human-Gate | keins | Human |
| Öffentliche Suchoberfläche fehlt | archiviert, kein Fake-Submit | `clustrmaps`/`peekyou` `external_unavailable`; Rescue-E-Mail ≠ Form-Proof | keins | Rescue-Lane |
| Session abgelaufen | Cleanup + fail | `revalidateConsumedSessionEffect` prüft `expires_at` | keins | Neu autorisieren |
| Restart während Write | durabler Intent | `submission_pending`/`submission_uncertain`, `recordSubmissionUncertain` | Reconcile nötig | `rightout_reconcile_submission` (separat approval-gated) |
| Nutzer bricht ab | vor Transport stoppen | `AbortSignal` in Scan/SMTP/Browser (`smtp:6,30`; `live-scan:121`) | keins | — |
| Teilweise erfolgreiche Kampagne | Zustand pro Broker | State-Machine + `partially_removed` | keins | Controller-Outcome-Review |
| **Autonome Discovery (new-state Broker)** | **Scan→persist→advance** | **F-1: persistiert nie, Endlos-Loop** | **Loop-Wedge, kein Write-Risiko** | **Assistierter Scan vorab, oder Fix** |

---

## F. Feature-Gap-Matrix (RightOut vs Unbroker/Wettbewerb)

| Feature | RightOut | Unbroker (Baseline) | Wettbewerber (Incogni/Optery/…) | Evidenz | Gap | Sev |
|---|---|---|---|---|---|---|
| Broker-Contract-Abdeckung | 22/22 normalisiert + 56 Core | 22 executable | Incogni 420+, Optery Hunderte | Kataloge, README | Datenmodell-Parität, nicht Breite | P2 |
| Discovery (real) | 21 US people-search Brave-Index | vergleichbar | Managed Scanner, private DBs | F-2/F-3 | keine private-DB/EU-Discovery | P2 |
| Autonomes Removal | approval-/campaign-gated, aber Discovery-Loop kaputt | halb-automatisch | vollmanaged | F-1 | Autonomie nicht lauffähig | P1 |
| Wiederholungsscans/Monitoring | `due_rechecks`, Cron-Surface, kein Dashboard | ähnlich | kontinuierlich + Dashboard | Code | kein Hosted-Monitoring | P3 |
| Reports/Export | MD/JSON/Sheets, PII-frei | Basis | Risk-Reports | `report-export.mjs` | — | — |
| Receipts/Verifikation | SMTP-Digest, IMAP, „submitted"≠„removed" | Basis | Provider-Response-Tracking | `parity-email`, `imap` | keine Screenshot/Before-After-Proof (ehrlich deklariert) | P3 |
| Datenschutzrechte | Art. 17/21-Template, DROP, CCPA | teils | teils | `references/legal/*` | rechtliche Wirkung `needs_evidence` | P2 |
| Familien/Multi-Profil | mehrere Profile via SecretRef | ja | ja | `authorizedProfileIds` | kein Admin-UI | P3 |
| Human-Assisted/Custom | Human-Lanes, kein Specialist-Service | teils | ja (managed) | Terms-Matrix | kein Managed-Service | P3 (ehrlich) |
| Sicherheits-/Approval-Modell | **stärker** (per-Effekt Bindung, SSRF-Guard, SecretRefs) | schwächer | proprietär | Code | Vorteil RightOut | — |

---

## G. Fehlende Evidenz (nur durch autorisierte Canaries/Provider/Recht beweisbar)

- Reale Broker-Zustellung/-Wirkung jeder Removal-Lane (alle Tests sind `.invalid`/gemockt) → `needs_evidence` (Doku sagt das selbst, „authorized canary protocol").
- Ob 8 „Automationsverbote"/14 „needs_evidence" die **aktuellen** Provider-Terms treffen (nicht gegen Live-Primärquellen re-verifiziert im Rahmen dieses Reviews) → `needs_evidence`.
- Exakte Feld-Konformität gegen die **aktuelle** OpenClaw Stable/Beta-Doku (SDK ist auf `2026.6.11` gepinnt; keine Live-Doku-Diff möglich in dieser Umgebung) → `needs_evidence`.
- Tatsächliche Wirksamkeit der SSRF-Abwehr hängt an der SDK-Implementierung `fetchWithSsrFGuard` (DNS-Rebinding/Private-IP) — hier korrekt *aufgerufen*, aber nicht SDK-intern auditiert → `needs_evidence`.
- Sigstore/SLSA-Attestierung des Artefakts existiert laut `release.yml` (`actions/attest@v4`), wurde hier aber nicht kryptografisch gegengeprüft (`gh attestation verify` nicht verfügbar) → `observed`.
- DSGVO-Rechtsgrundlage/Provider-Automation-Erlaubnis → juristisch, `needs_evidence`.

---

## H. Positiv bestätigte Eigenschaften (selbst belegt)

- Tag `v0.8.0` (`2ade80b`) → Commit `704b020` = lokaler HEAD; Tag-Liste korrekt.
- TGZ-SHA256 `d2fdc365…` konsistent über Asset-Digest, `RELEASE-SHA256SUMS`, `RELEASE-EVIDENCE.json`, lokalen Hash.
- **Byte-genaue Reproduzierbarkeit** von `dist/index.js` + 21 `dist/lib/*.mjs` aus der Quelle; kein Source/Dist-Drift; Paket = Working-Tree (71 Dateien).
- `npm-shrinkwrap.json` ≡ `package-lock.json`; SBOM 47 = 47 Non-Dev-Deps; `npm audit --omit=dev --audit-level=high` = 0.
- Approval-Bindung: deterministisch, param-neu-berechnet, single-use, host-`toolCallId`-gebunden, TTL 120 s → TOCTOU-/Replay-fest. Kampagnen-Grant bindet Profil-/Katalog-/Runtime-Digest.
- Live-Scan: `not_found` hart 0, „keine Treffer" nie als Abwesenheit; `inconclusive`-Semantik korrekt; Kandidaten-URLs nie persistiert/zurückgegeben.
- SSRF: HTTPS-erzwungen, Host-Allowlist, `maxRedirects:0`, Timeouts; Brave-URL konstant.
- SMTP: kein Header-Injection-Vektor, TLS erzwungen (`rejectUnauthorized`, `minVersion TLSv1.2`), Abort-sicher.
- State-Machine schützt `partially_removed`/`request_rejected`/`identity_verification_required` gegen Scan-Überschreibung.
- Installer `install.sh`: `set -euo pipefail`, Symlink-Ablehnung (Quelle+Vorfahren+Config+Managed-Dir), atomarer `mkdir`-Lock, `mktemp`-Transaktion, Tar-Backup + Rollback, Trap-Cleanup.
- Parity-Ehrlichkeit: 8 Verbote + 14 needs_evidence + 0 Erlaubnisse exakt belegt; README trennt Contract- von Capability-Parität sauber.
- Tests grün (282/1 skip), Coverage 94,2/81,1/87,3, Python 50 OK, `release_check.py` ok.

---

## I. Finaler Release-Entscheid

**Was einen Release verhindert:** Genau F-1. Die als funktionierend ausgelobte autonome globale Scan-Kampagne persistiert ihre Discovery nie (`recordScan` lehnt den Kampagnen-Modus ab), läuft in eine Endlosschleife und erreicht nie Removal. Die Release-Notes-Aussage „drains 59 combined catalog lanes in bounded four-route campaign batches" ist damit code-widerlegt. Das ist mein einziger echter Blocker — aber ein harter, weil es die Kern-Wertaussage betrifft.

**Was vor Release korrigiert werden muss:**
- F-1 fixen (`recordScan` beide Scan-Modi akzeptieren **oder** Mode vor `recordScan` normalisieren) **plus** ein echter E2E-Regressionstest der Kette `campaign_next → live_scan(campaignId) → durable_case_recorded===true → Fortschritt/done_for_now`. Ohne diesen Test bleibt die Lücke unsichtbar.
- Falls nicht gefixt: alle Autonomie-/„59-Lanes"-/„global autonomous scan"-Aussagen aus Release Notes, README und `approval-boundary.md` streichen und den Modus als „assistierter Scan + approval-gated Removal" auszeichnen.

**Was nach Release als Hardening akzeptabel wäre:** F-4 (impliziter US-Default), F-5 (Batch-Verlust bei geschütztem Zustand), F-6 (Tag-Signatur/Prerelease-Konsistenz).

**Welche Aussagen abgeschwächt werden müssen:**
- „59 Scan-Lanes" → „21 code-durchsetzbare Brave-Scan-Lanes (US people-search); 59 = Katalog-Domains".
- „Live-Scan funktioniert für alle Länder" → „technische Länderakzeptanz für alle ISO-Länder; reale öffentliche Discovery beschränkt auf US-People-Search-Broker".
- „Autonomer Betrieb" → erst nach F-1-Fix zulässig.

**Würde ich v0.8.0 persönlich freigeben?** Nein — nicht wie ausgelobt. Der assistierte Kern ist ungewöhnlich sauber und sicherheitsbewusst gebaut (Approval-Bindung, Reproduzierbarkeit, SSRF/SMTP-Härtung, ehrliche Parity-Sprache), und ich würde ihn nach dem F-1-Fix + Regressionstest freigeben. Aber solange die Headline-Autonomie im veröffentlichten Paket nachweislich nicht funktioniert und die Release-Notes das Gegenteil behaupten, ist es ein NO-GO. Der Fix ist klein; nach ihm ist es ein GO WITH CONDITIONS.

---

*Erstellt: 2026-07-13 · Read-only Review, keine Repository-Änderungen, keine realen Provider-Writes · synthetische Identitäten/Mocks.*
