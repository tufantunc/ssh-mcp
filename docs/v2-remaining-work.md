# SSH MCP v2 — Remaining Work / TODO

> Updated: 2026-07-11. Reflects all completed work.

---

## Tamamlanan (11 madde)

| Madde | Tarih | Açıklama |
|-------|-------|----------|
| WD-1 | 2026-07-11 | OS Keychain wire (`initKeychain()`) |
| WD-2 | 2026-07-11 | ProxyJump wire (`via` field → `forwardOut`) |
| WD-3 | 2026-07-11 | SSH CA certs wire (`cert` → auto-detect `-cert.pub`) |
| WD-4 | 2026-07-11 | OPA docs + README update |
| P1-A | 2026-07-11 | Progress notifications (500ms throttled, bytes + stdout tail) |
| P1-B | 2026-07-11 | Cancel handler (AbortSignal → stream signal) |
| P1-C | 2026-07-11 | MCP Resources (`ssh://connections`, `ssh://connections/{profile}`, `ssh://sessions/{profile}/{session}`) |
| P2-H | 2026-07-11 | HTTP Rate Limiting (token-bucket, MCP-aware 429 + Retry-After, 1MB body cap) |
| P2-J | 2026-07-11 | CodeQL in CI (security-extended + security-and-quality) |
| P2-M | 2026-07-11 | Compliance Mapping (SOC 2, PCI-DSS, ISO 27001, HIPAA) |
| P2-N | 2026-07-11 | Tool-description hash (`--dumpToolHashes`, release artifact) |

## İptal Edilen (2 madde)

| Madde | Sebep |
|-------|-------|
| P1-D Composite session ref (`@`) | Düşük değer — LLM explicit parametrelerle daha iyi çalışır |
| P2-E Interactive password prompt | MCP uyumsuz — stdin JSON-RPC pipe, TTY değil |

---

## Kalan Maddeler (9)

### Kolay (2/5)

#### P2-I: changesets Release Pipeline
- **Açıklama:** Conventional Commits + `@changesets/cli` ile otomatik version bump, changelog, release
- **Efor:** Config + CI workflow (~1 saat)
- **Değer:** Release süreçni otomatikleştirir, changelog üretir

### Orta (3/5 — her biri ~yarım gün)

#### P2-A: JIT Approval Tokens (HMAC, TTL)
- **Açıklama:** Kullanıcı destructive komutu onaylar → 5dk geçerli HMAC-signed token → aynı komut tekrar çalışınca token ile auto-approve
- **Değer:** Tekrarlayan destructive komutlarda approval friction'ı azaltır
- **Risk:** Token çalınırsa 5dk boyunca abuse edilebilir — ama HMAC-signed, specific command'a bound

#### P2-B: asciinema Session Recording
- **Açıklama:** Interactive session I/O'yu asciinema cast v2 formatında kaydet, `asciinema play` ile replay
- **Değer:** Forensic replay — "agent ne yaptı?" sorusunu görsel olarak yanıtlar
- **Opsiyonel:** `--recordSessions` flag ile açma/kapama

#### P2-C: OTEL Tracing
- **Açıklama:** OpenTelemetry span'ları — MCP requestId → SSH exec → policy evaluation arasındaki correlation
- **Değer:** Dağıtık sistemlerde observability — "hangi MCP isteği hangi SSH komutunu tetikledi?"
- **Dependency:** `@opentelemetry/api` (~50KB)

#### P2-D: age-encrypted Config Sections
- **Açıklama:** TOML config'de `[profiles.secrets]` bölümünü `age` ile şifrele, passphrase ile decrypt
- **Değer:** Config dosyası disk'te şifreli — `0600`'e ek bir koruma katmanı
- **Dependency:** `age-encryption` npm paketi veya CLI wrapper

#### P2-F: Dynamic Connections
- **Açıklama:** Client tool çağrısında `host`, `user`, `port` verir, config'de tanımlı olmayan host'lara bağlanır
- **Değer:** Esneklik — önceden tanımlanmamış host'lara erişim
- **Risk:** Prompt-injected agent yeni host'a bağlanabilir — `allowDynamicConnections: true` explicit opt-in, lowest-trust default ile

#### P2-K: Sigstore Audit Signing
- **Açıklama:** Hash-chain audit log'a ek olarak günlük sigstore/cosign keyless root signing
- **Değer:** Audit log'un cryptographically verifiable olması — high-assurance environments için
- **Dependency:** `sigstore-js`

#### P2-L: Per-Agent Command Quotas
- **Açıklama:** Her agent/client için günlük komut sayısı limiti (örn: günde 500 komut), circuit breaker
- **Değer:** Runaway agent koruması — prompt-injected agent sınırsız komut çalıştıramaz
- **Config:** `commandQuotaPerDay` profile veya defaults seviyesinde

### Çok Büyük (5/5)

#### P2-G: WebUI (Approval Queue + Audit Viewer)
- **Açıklama:** Hono HTTP server + minimal SPA — connection status, live approval queue, audit log viewer
- **Değer:** HTTP transport kullananlar için görsel yönetim paneli
- **Efor:** ~500+ satır, yeni dependency (Hono + Preact/htmx), ayrı bir sub-project gibi
- **Öneri:** v2.1 veya v2.2'ye ertele

---

## Önerilen Sıra

1. **P2-I** changesets (2/5 — kolay, release'i otomatikleştirir)
2. **P2-L** Per-agent quotas (3/5 — güvenlik değeri yüksek, runaway agent koruması)
3. **P2-A** JIT tokens (3/5 — UX iyileştirmesi, approval friction)
4. **P2-F** Dynamic connections (3/5 — esneklik, ama güvenlik dikkat ister)
5. **P2-D** age config (3/5 — security hardening)
6. **P2-B** asciinema (3/5 — forensic replay)
7. **P2-C** OTEL tracing (3/5 — observability)
8. **P2-K** Sigstore (3/5 — high-assurance audit)
9. **P2-G** WebUI (5/5 — büyük, sonraya)

---

## Güncel İstatistik

| Kategori | Toplam | Tamamlandı | İptal | Kalan |
|----------|:------:|:----------:|:-----:|:-----:|
| P0 Security | 10 | 10 | 0 | 0 |
| P1 Core Features | 7 | 4 | 1 | 2 → 0 (hepsi yapıldı/iptal) |
| P2 Hardening | 14 | 11 | 1 | 2 |
| Session Arch | 7 | 7 | 0 | 0 |
| Dead Code (WD) | 4 | 4 | 0 | 0 |
| **Toplam** | **42** | **36** | **2** | **9** |

153 test, 22 kaynak dosyası, 19 modül.
