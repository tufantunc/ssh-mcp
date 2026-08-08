# SSH MCP v2 — Remaining Work / TODO

> Updated: 2026-08-08. Backlog kapandı — kalan iki madde bilinçli olarak v2.1'e ertelendi.

---

## Tamamlanan (15 madde)

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
| **P2-C** | 2026-08-08 | **OTEL Tracing** — `src/observability/tracer.ts`, `--otelEndpoint` / `--otelServiceName`; span'lar connection, session ve policy katmanlarında. Bağımlılıklar beyan edildi (`@opentelemetry/resources`, `semantic-conventions` — önceden yalnızca npm hoisting sayesinde çözülüyordu) |
| **P2-I** | 2026-08-08 | **changesets Release Pipeline** — major changeset eklendi (`changeset status` → 2.0.0), `changesets.yml` workflow, README migration bölümü, kaldırılan v1 flag'leri için startup guard |
| **P2-L** | 2026-08-08 | **Per-Profile Command Quota** — `commandQuotaPerDay`, kayan 24s penceresi, policy sonrası enforce, `command-quota` ruleId ile audit |
| **P2-A** | 2026-08-08 | **JIT Approval Grants** — `approvalGrantTtlMs`, tam komut + profil + sınıfa bağlı, `approver: "jit-grant"` ile audit, varsayılan kapalı |

## İptal Edilen (6 madde)

| Madde | Sebep |
|-------|-------|
| P1-D Composite session ref (`@`) | Düşük değer — LLM explicit parametrelerle daha iyi çalışır |
| P2-E Interactive password prompt | MCP uyumsuz — stdin JSON-RPC pipe, TTY değil |
| **P2-B** asciinema Session Recording | Kayıt, projenin her yerde uyguladığı redaksiyonu delerdi: ham session I/O'su (sudo şifresi, dosya içerikleri) diske yazılır. Redaksiyon uygulanırsa replay bozulur, uygulanmazsa sır sızar. Değeri bu tavizi karşılamıyor |
| **P2-D** age-encrypted Config | Doküman yazıldığında credential'lar config dosyasındaydı; **v2'de çıkarıldılar** (agent → keychain → env → key file). Geriye şifrelenecek olarak yalnızca host adları ve policy kalıyor, onlar da zaten `0600`/`0700` altında. Yeni bir crypto bağımlılığının koruyacağı şey kalmadı |
| **P2-F** Dynamic Connections | README'nin uyardığı lethal trifecta'yı doğrudan genişletiyor: prompt-injected agent önceden tanımlanmamış bir host'a bağlanabilir. Opt-in ile daraltılabilirdi ama kazanılan esneklik riski karşılamıyor |
| **P2-K** Sigstore Audit Signing | Mevcut hash-chain zaten tamper-evident. Sigstore bunu dışarıdan doğrulanabilir yapardı, ama yalnızca uyumluluk denetimi olan ortamlarda değer katıyor — yeni bağımlılığı şu an haklı çıkarmıyor |

---

## Kalan (2 madde — v2.1)

#### P2-G: WebUI (Approval Queue + Audit Viewer)
- **Açıklama:** HTTP server + minimal SPA — connection status, live approval queue, audit log viewer
- **Efor:** ~500+ satır, yeni dependency, ayrı bir sub-project gibi
- **Durum:** v2.1/v2.2'ye ertelendi. Açık PR'lar: #60, #61, #62, #63

#### PR #64: Config Hot-Reload
- **Açıklama:** TOML config değişikliklerini yeniden başlatmadan uygula
- **Not:** `SessionManager` ve `CommandQuota` artık profili **çağrı anında** okuyor (constructor'da snapshot almıyor), yani hot-reload için gereken şekil hazır
- **Durum:** v2.1'e ertelendi

---

## Güncel İstatistik

| Kategori | Toplam | Tamamlandı | İptal | Kalan |
|----------|:------:|:----------:|:-----:|:-----:|
| P0 Security | 10 | 10 | 0 | 0 |
| P1 Core Features | 7 | 6 | 1 | 0 |
| P2 Hardening | 14 | 9 | 5 | 1 (WebUI) |
| Session Arch | 7 | 7 | 0 | 0 |
| Dead Code (WD) | 4 | 4 | 0 | 0 |
| **Toplam** | **42** | **36** | **6** | **1** |

**270 test, 33 test dosyası, 25 kaynak dosyası.**

> Yayın durumu için `docs/v2-release-readiness-report.md`'ye bakın. 2.0.0 etiketi
> öncesi kalan tek gerçek koşul, o rapordaki §5 manuel doğrulama turu.
