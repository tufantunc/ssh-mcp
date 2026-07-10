# SSH MCP v2 — Remaining Work / TODO

> Generated from gap analysis against `research/v2-security-research-report.md` and `research/v2-session-architecture.md`.
> Last updated: 2026-07-10

---

## ⚠️ Wired Edilmemiş Kod (Dead Code — Düşük Efor, Yüksek Değer)

Bu maddelerin implementasyonu kodda var ama `index.ts` veya `connection.ts`'ten çağrılmıyor. Kullanıcı erişemiyor.

### WD-1: OS Keychain entegrasyonu çağrılmıyor
- **Dosya:** `src/config/credential-resolver.ts` — `initKeychain()` export edilmiş ama hiç çağrılmıyor
- **Düzeltme:** `src/index.ts` `main()` fonksiyonunda `await initKeychain()` çağrısı ekle
- **Efor:** 1 satır
- **Durum:** Detaylı tartışma aşağıda

### WD-2: ProxyJump (`via` field) kullanılmıyor
- **Dosya:** `src/ssh/connection.ts` — `profile.via` alanı types'te var, config schema'da var, ama `connect()` kullanmıyor
- **Beklenen:** `via: "bastion"` profili, bağlantıyı bastion üzerinden socks ile routlamalı (`connectConfig.sock`)
- **Düzeltme:** `connect()` içinde, eğer `profile.via` set ise, önce bastion profile'ına bağlan, sonra onun `Client`'ını sock olarak kullan
- **Efor:** ~30 satır

### WD-3: SSH CA Certificates (`cert`, `caFingerprint`) kullanılmıyor
- **Dosya:** `src/ssh/connection.ts` — `profile.cert` ve `profile.caFingerprint` alanları types'te var ama `connectConfig`'e geçirilmiyor
- **Düzeltme:** `ssh2` `ConnectConfig`'e `certificate` ve ilgili alanları ekle
- **Efor:** ~10 satır

### WD-4: OPA entegrasyonu dokümante değil
- **Dosya:** `src/policy/engine.ts` — `evaluateWithOpa()` çalışıyor ama README'de `--opa-url` yeterince açıklanmamış
- **Düzeltme:** README'ye OPA örnek bölümü ekle
- **Efor:** Dokümantasyon

---

## ❌ Atlanan P1 Özellikleri (Kullanıcı Deneyimini Etkiliyor)

### P1-A: `notifications/progress` streaming
- **Açıklama:** Uzun süren komutlarda (build, deploy, tail) MCP progress notification gönder — client'a byte counter + stdout tail göster
- **Spec referansı:** Raporda P1-16, `notifications/progress` MCP spec
- **Efor:** Orta — `exec()` içine progress callback, `tools/call`'a `progressToken` desteği

### P1-B: `notifications/cancelled` MCP handler
- **Açıklama:** Client iptal isteği gönderdiğinde (`notifications/cancelled`) çalışan komuta signal gönder
- **Spec referansı:** Raporda P0-9 kısmen yapıldı (timeout), ama client-initiated cancel yok
- **Efor:** Düşük — MCP server cancel event'ini dinle, active stream'e signal gönder

### P1-C: MCP Resources (`ssh://connections/*`)
- **Açıklama:** Profile'ları MCP resource olarak expose et — client keşfedebilir, tool çağırmadan önce ne var görebilir
- **Spec referansı:** Rapor Section 7, "profiles can be exposed as MCP resources"
- **Efor:** Düşük — `server.resource()` ile 3 endpoint

### P1-D: Composite session ref (`session@profile`)
- **Açıklama:** `run-command(session="deploy@prod-web-1")` shorthand syntax
- **Spec referansı:** Session architecture doc, "Option B — composite ref"
- **Efor:** Düşük — `@` parse logic, ~10 satır

---

## ❌ Atlanan P2 Özellikleri (Nice-to-Have)

### P2-A: JIT Approval Tokens (HMAC, TTL)
- **Açıklama:** Time-bounded signed approval token — kullanıcı bir destructive komutu onaylar, token 5dk geçerli, aynı komut tekrar çalıştırılırsa token ile approve edilir
- **Spec referansı:** Rapor Section 5, "JIT/time-bounded approval tokens"
- **Efor:** Orta — HMAC signing, token store, policy engine entegrasyonu

### P2-B: asciinema Session Recording
- **Açıklama:** Interactive session'ları asciinema cast formatında kaydet, replay edilebilir
- **Spec referansı:** Rapor Section 5, "optional asciinema session recording"
- **Efor:** Orta — cast format writer, session event capture

### P2-C: OTEL Tracing
- **Açıklama:** OpenTelemetry distributed tracing — MCP requestId → OTEL span correlation
- **Spec referansı:** Rapor Section 6, "OTEL traces"
- **Efor:** Orta — `@opentelemetry/api`, span creation, exporter config

### P2-D: age-encrypted Config Sections
- **Açıklama:** TOML config'de şifreli credential bölümleri — `age` ile encrypt, passphrase ile decrypt
- **Spec referansı:** Rapor Section 3, "age-encrypted profile sections"
- **Efor:** Orta — age CLI wrapper veya `age-encryption` npm paketi

### P2-E: Interactive Password Prompt
- **Açıklama:** Config'de credential yoksa, başlangıçta TTY'den şifre iste
- **Spec referansı:** Rapor Section 3, "interactive prompt at startup"
- **Efor:** Düşük — `readline` ile stdin'den şifre oku

### P2-F: Dynamic Connections
- **Açıklama:** Client tool çağrısında host bilgisi verir, server dinamik olarak bağlanır
- **Spec referansı:** Rapor Section 7, Issue #41, "dynamic connections (off by default)"
- **Efor:** Orta — yeni tool param'ları, güvenlik kontrol'ları, lowest-trust default

### P2-G: WebUI (Approval Queue + Audit Viewer)
- **Açıklama:** Minimal web dashboard — connection status, live approval queue, audit log viewer
- **Spec referansı:** Rapor Section 8, PRs #60-#63, "minimal dashboard"
- **Efor:** Yüksek — Hono server + SPA (Preact/htmx)

### P2-H: HTTP Rate Limiting
- **Açıklama:** HTTP transport'da token-bucket per token/IP rate limiting
- **Spec referansı:** Rapor Section 8, "rate limiting & abuse prevention"
- **Efor:** Düşük — `@fastify/rate-limit` veya manuel token-bucket

### P2-I: changesets Release Pipeline
- **Açıklama:** Conventional Commits + changesets ile otomatik version bump ve changelog
- **Spec referansı:** Rapor Section 9, "changesets vs semantic-release"
- **Efor:** Düşük — `@changesets/cli` init, CI workflow

### P2-J: CodeQL in CI
- **Açıklama:** GitHub CodeQL SAST analysis, Semgrep'e ek olarak
- **Spec referansı:** Rapor Section 9, "CodeQL (security-extended)"
- **Efor:** Düşük — `github/codeql-action/init+analyze` CI step

### P2-K: Sigstore Audit Signing
- **Açıklama:** Hash-chain audit log'a ek olarak günlük sigstore root signing
- **Spec referansı:** Rapor Section 6, "sigstore/cosign keyless root signing"
- **Efor:** Orta — `sigstore-js` entegrasyonu

### P2-L: Per-Agent Command Quotas
- **Açıklama:** Her agent/client için günlük komut sayısı limiti, circuit breaker
- **Spec referansı:** Rapor Section 4, "rate limits, quotas, circuit breakers"
- **Efor:** Orta — quota store, policy engine entegrasyonu

### P2-M: Compliance Framework Mapping
- **Açıklama:** SECURITY.md'ye SOC 2 / PCI-DSS / ISO 27001 / HIPAA kontrol mapping'i ekle
- **Spec referansı:** Rapor Section 6, "document the SOC2/PCI/ISO27001/HIPAA mapping"
- **Efor:** Düşük — Dokümantasyon

### P2-N: Tool-Description Hash per Release
- **Açıklama:** Her release'te tool açıklamalarının hash'ini yayınla — guard proxy'ler rug-pull detection için
- **Spec referansı:** Rapor Section 1, "publish the tool-description hash"
- **Efor:** Düşük — build script + README

---

## Öncelik Sırası (Önerilen)

1. **WD-1** — `initKeychain()` çağrısı (1 satır, hemen)
2. **WD-2** — ProxyJump wire etme (~30 satır)
3. **WD-3** — SSH cert wire etme (~10 satır)
4. **P1-A** — Progress notifications
5. **P1-B** — Cancel handler
6. **P1-C** — MCP resources
7. **P1-D** — Composite session ref
8. **P2-I** — changesets pipeline
9. **P2-J** — CodeQL CI
10. Geri kalan P2 maddeleri ihtiyaca göre

---

## İstatistik

| Kategori | Toplam | Tamamlandı | Kalan |
|----------|:------:|:----------:|:-----:|
| P0 Security | 10 | 10 | 0 |
| P1 Core Features | 17 | 13 | 4 |
| P2 Hardening | 15 | 6 | 9 |
| Session Arch | 7 | 7 | 0 |
| Dead Code (WD) | 4 | 0 | 4 |
| **Toplam** | **53** | **36** | **17** |
