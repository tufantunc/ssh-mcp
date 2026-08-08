# ssh-mcp v2 — Yayına Hazırlık Raporu

> İlk sürüm: 2026-08-08 · **Güncellendi: 2026-08-08 (düzeltmeler sonrası)**
> Branch: `v2` (main'e göre 62 commit, 101 dosya, +12.797/-1.666)
> Yöntem: build + test çalıştırma, 8 uzman kod incelemesi (security, correctness, backend, tests, performance, craft, ai-antipatterns, api-contract), açık issue/PR eşlemesi, ardından bulguların düzeltilmesi ve her düzeltmenin testle doğrulanması.

---

## 1. Özet Karar

**Verdict: APPROVE (koşullu) — gerçek sunucuda manuel doğrulama turundan sonra 2.0.0 etiketlenebilir.**

İlk incelemede yayını bloke eden 9 madde ve 12 yüksek öncelikli madde vardı. **Tamamı kapatıldı.** Ek olarak, düzeltme sürecinde ilk incelemenin bulamadığı 5 hata daha ortaya çıktı (aşağıda ⚡ ile işaretli) — çünkü test kapsamı eklenene kadar görünür değillerdi.

| Ölçüt | İlk durum | Şimdi |
|---|---|---|
| Test sayısı | 183 | **248** |
| Suite durumu | 182/183 (1 kırmızı) | **248/248**, 3 ardışık koşuda kararlı |
| Build + typecheck | build temiz, testler tsc dışında | **ikisi de temiz** (`npm run typecheck` eklendi) |
| Yayın bloke eden | 9 | **0** |
| Yüksek öncelikli | 12 | **0** |

**Kalan iş yayını bloke etmiyor** ama yapılması önerilir: gerçek bir MCP istemcisiyle manuel doğrulama turu (§5).

---

## 2. Build ve Test Durumu

| Kontrol | Sonuç |
|---|---|
| `npm run build` (tsc) | ✅ Temiz |
| `npm run typecheck` (src + test) | ✅ Temiz — **yeni**, testler önceden tsc kapsamı dışındaydı |
| `npm test` | ✅ **248/248** (31 dosya) |
| Ardışık koşu kararlılığı | ✅ 3/3 temiz |

### Test kapsamındaki büyümenin nedeni

Eklenen test grupları:
- **MCP handler katmanı** — 28 test (`test/unit/tools/`). Önceden **sıfır** kapsam vardı; istemcinin gerçekten çağırdığı katman buydu.
- **Host-key doğrulaması** — 7 entegrasyon testi. Önceden entegrasyon testlerinin *tamamı* `'insecure'` moduyla bağlanıyordu.
- **ProxyJump** — 4 test + forwarding açık bastion container'ı. Önceden sıfır kapsam.
- **stdin lifecycle** — 2 test (#53).
- **`sanitizeCommand` property testleri**, denylist/group/cascade/deny-mode testleri, SFTP kanal ve cap testleri, background satır bütünlüğü testi, session yeniden-açma yarışı testi.

### Doğrulama yöntemi

Kritik düzeltmelerin her biri için **düzeltme geçici olarak kaldırılıp testin gerçekten düştüğü doğrulandı**:

| Düzeltme | Kaldırılınca |
|---|---|
| `sftp.end()` | `CHANNEL_OPEN_FAILURE` |
| `sanitizeCommand` kontrol karakteri temizliği | 3 test düşüyor |
| ProxyJump reconnect | reconnect testi düşüyor |
| `hostVerifier` | 7 testten 5'i düşüyor |
| `open-session` annotations | session testi düşüyor |
| Background satır birleştirme | uzun-satır testi düşüyor |
| Session eviction guard | yeniden-açma testi düşüyor |
| stdin EOF handler | 8 sn timeout'a kadar asılı kalıyor |

Bir property testinin **kendisi de düzeltildi**: `fc.string()` varsayılan olarak CR/LF/NUL üretmediği için sanitizer kaldırıldığında bile geçiyordu. Üreteç bu karakterleri içerecek şekilde değiştirildi.

---

## 3. Kapatılan Bulgular

### Yayını bloke edenler (9/9)

| # | Bulgu | Çözüm |
|---|---|---|
| B1 | Komut hataları başarı görünüyordu (`exitCode`/`stderr` atılıyordu) | Sıfır olmayan çıkış artık `isError` + redakte stderr + exit code. PR #66/#67'nin konusunu kapatır |
| B2 | `curl`/`wget` "read-only" sayılıyordu → SSRF, veri sızdırma, uzak dosya yazma | Allowlist'ten çıkarıldı; `safe` sınıfına düşüyor, policy altında kullanılabilir |
| B3 | SFTP kanal sızıntısı (~10 işlemde `MaxSessions` doluyordu) | `finally { sftp.end() }`; issue #34 sınıfını kapatır |
| B4 | `approvalPolicy = "deny"` reddetmiyordu | Gerçek deny kararı. Hatayı sabitleyen mevcut test düzeltildi |
| B5 | `[defaults]` anahtarlarının çoğu uygulanmıyordu | Tam cascade; `workdir` uygulandı; `hostFingerprint`/`caFingerprint` kaldırıldı; şemalar `.strict()` |
| B6 | HTTP tek istemci destekliyordu, sonra kalıcı ölüyordu | Session başına transport + `MAX_SESSIONS` sınırı. Canlı doğrulandı |
| B7 | Onay akışı `as any` ile elle yazılmıştı | SDK'nın tipli `elicitInput()`'u; fail-closed korundu ama artık loglanıyor |
| B8 | SFTP indirmede boyut sınırı yoktu | `stat` + stream seviyesinde çift cap |
| B9 | 413 keep-alive soketini zehirliyordu (EPIPE) | `Connection: close` + flush sonrası destroy |
| B10 | 5 eski v1 test dosyası commit edilmemişti | Commit edildi |
| B11 | Sürüm 1.5.0, changeset yok, migration yok | Major changeset (→ **2.0.0** doğrulandı), README migration bölümü, kaldırılan v1 flag'leri için startup guard |

### Yüksek öncelikli (12/12)

`sanitizeCommand` property testi · handshake timer temizliği · ProxyJump reconnect · audit bütünlüğü (çalışıp başarısız olan komut artık "deny" yazılmıyor) · sanitize reddinin audit'lenmesi · OPA fail-open loglaması · tek denylist kaynağı · açık `group` alanı · bağımlılık beyanları (OTEL, keyring, engines) · session buffer taraması · SFTP denylist · host-key kapsamı.

> **Not — H5'te ilk yaklaşım yanlıştı:** İki denylist'i körlemesine birleştirmek `rm -rf /tmp/x`'i onayla bile çalışamaz hale getirdi. Listeler aslında **farklı iki şeydi**: `FORBIDDEN_PATTERNS` (asla) ve `DESTRUCTIVE_PATTERNS` (onayla). Ayrım açıkça kuruldu.

### ⚡ Düzeltme sürecinde ortaya çıkan yeni hatalar (5)

Bunlar ilk incelemede **bulunamamıştı** — test kapsamı eklenmeden görünür değillerdi:

| Bulgu | Etki | Nasıl bulundu |
|---|---|---|
| ⚡ **`open-session` MCP üzerinden tamamen çalışmıyordu** | v2'nin başlıca özelliği ölü halde yayına gidiyordu. `{}` annotations slotuna geçilmişti; SDK boş nesneyi Zod şeması sayıyor (`isZodRawShape({})` → `true`), callback slotunu yutuyor → her çağrı `"cb is not a function"` | İlk handler testi çalıştığında |
| ⚡ Policy reddi audit'e sahte kayıt yazıyordu | Denylist/onay reddi gerçek kararı taşımıyordu | Handler audit testleri |
| ⚡ Audit `ruleId` kaydetmiyordu | Denylist mi role-binding mi ayırt edilemiyordu | Handler audit testleri |
| ⚡ Komut çıktısında entropy taraması kapalıydı | `env` dökümü yüksek entropili sırları modele veriyordu | Redaksiyon testi |
| ⚡ Interactive session çıktı ayrıştırması yanlıştı | Satır sayma + `printf` heuristiği; PTY echo sırasına bağlı bozulma | Ardışık koşu kararlılık analizi |
| ⚡ Background çıktısı bozuluyordu | Chunk sınırında satır bölünmesi + her chunk arası boş satır | Uzun-satır regresyon testi |
| ⚡ 7 mevcut tip hatası | Testler tsc kapsamı dışındaydı | `tsconfig.test.json` eklenince |

---

## 4. Kalan İş (yayını bloke etmez)

| Madde | Durum | Neden ertelendi |
|---|---|---|
| `SessionManager` çıkarımı | 🔄 **Devam ediyor** | `SSHConnection` 464 satır; session yönetimi ayrı sorumluluk |
| `tools/registry.ts` 704 satır | Açık | Boru hattı konsolide edildi ama dosya hâlâ büyük |
| PR #64 config hot-reload | Açık | Yeni özellik |
| PR #60-#63 WebUI | v2.1'e ertelendi | `docs/v2-remaining-work.md`'de zaten planlı |
| `docs/v2-remaining-work.md` 9 maddesi | Açık | JIT token, asciinema, age config, quotas, sigstore, WebUI |
| Issue #27 "description sonrası çıktı yok" | ❓ Belirsiz | v2'de `description` parametresi kaldırıldı; manuel doğrulama gerekli |

### Test altyapısı hakkında bilinen kısıt

`vitest.config.ts`'te `fileParallelism: false` **gerekli**. Paralellik açıkken entegrasyon dosyaları eşzamanlı SSH handshake sayısını katlıyor ve bağlantılar handshake öncesi düşüyor — testler hem hata veriyor hem de *sessizce atlanıyor*. Ölçüldü: paralellikle 2 hata/4 atlanan ile başlayıp ikinci koşuda dosya dosya çöküyor; serileştirilmiş halde 8 ardışık koşu temiz. Süre farkı yok (~24 sn).

Bu yerel macOS/Docker Desktop port yönlendirme katmanının bir özelliği (sshd hiçbir şey loglamıyor, ham TCP sorunsuz, ~30 sn'de kendiliğinden düzeliyor) ve aynı desen düzeltmeler öncesi baseline'da da görüldü. CI Linux'ta service container'larla doğrudan ağ kullandığı için oraya yansıması beklenmiyor — **ama bu doğrulanmadı.**

---

## 5. Gerçek Sunucuda Doğrulama — hâlâ öneriliyor

Otomatik kapsam ilk rapordakinden çok daha iyi, ama şunlar hâlâ manuel doğrulama istiyor:

- [ ] Gerçek bir MCP istemcisiyle (Claude Desktop / MCP Inspector) 11 tool'un tamamı — özellikle **`open-session`**, çünkü MCP üzerinden hiç çalışmadığı yeni ortaya çıktı
- [ ] Onay akışı: gerçek bir istemcide destructive komutun prompt üretmesi ve reddedilince çalışmaması
- [ ] Başarısız bir komut → istemcinin hata gördüğünü doğrula
- [ ] `read-command` ile `curl` dene → reddedildiğini gör
- [ ] `[defaults] approvalMode = "ask-all"` koy, profilde `approvalPolicy` yazma → uygulandığını gör
- [ ] HTTP transport'a iki istemci bağla, birincisini kopar, üçüncüyü bağla
- [ ] Temiz makinede TOFU: ilk bağlantı kaydı, fingerprint bozunca red
- [ ] `--hostKeyMode=strict` ile bilinmeyen host → red
- [ ] `via` ile bastion üzerinden bağlan, bağlantıyı düşür, tekrar dene
- [ ] `pnpm install` ile kurup `--otelEndpoint` dene
- [ ] Issue #27'yi (çıktı yok) mevcut sürümde tekrar üretmeyi dene
- [ ] CI'ı bir kez Linux'ta çalıştırıp `SSH_MCP_REQUIRE_SERVERS=1` ile yeşil olduğunu gör

---

## 6. Issue/PR Kapsama Durumu (güncel)

**Kapsanmış:**

| Issue/PR | Durum |
|---|---|
| #44 Command Injection | ✅ sanitizer + property test + PoC regresyonu |
| #42, #43 Log'da bilgi ifşası | ✅ 3 katmanlı redaksiyon, artık komut çıktısında da entropy taraması |
| #47, #51, #37 zod/SDK | ✅ |
| #32 Env var | ✅ |
| #25, #35 Şifreli key | ✅ |
| #46 Elevation ayrımı | ✅ |
| #55, #56, #58, #59 TOML/audit/approval | ✅ |
| #28, #41, #38 Docker/HTTP/SFTP | ✅ HTTP artık çoklu session |
| #34 PTY/kanal tükenmesi | ✅ exec **ve** SFTP tarafı |
| #36, #23 read-only ayrımı | ✅ `curl`/`wget` çıkarıldıktan sonra iddia geçerli |
| #66, #67 exit code vs stderr | ✅ B1 ile kapandı |
| #53 stdin kapanınca çık | ✅ Testli |
| #45 `--workdir` | ✅ Uygulandı (exec, background, interactive) |

**Kapsanmamış:** #64 (hot-reload), #60-#63 (WebUI, bilinçli ertelendi), #27 (belirsiz — manuel doğrulama gerekli), #33 (lethal trifecta: yapısal risk, B2 ile önemli ölçüde daraltıldı).

---

## 7. Sonuç

İlk raporun tespiti — "sorun tasarımda değil, son %10'un tamamlanmamış olmasında" — doğruydu ve o %10 kapatıldı. Baskın örüntü olan "şema/dokümanda tanımlı ama son bağlantısı kurulmamış özellik" sistematik olarak giderildi.

Süreç ayrıca ilk incelemenin yakalayamadığı 5+ hatayı ortaya çıkardı; hepsi test kapsamı eklendikten sonra görünür oldu. Bunlardan biri (`open-session`) v2'nin başlıca özelliklerinden birini tamamen işlevsiz bırakıyordu.

Manuel doğrulama turu (§5) tamamlandıktan sonra **2.0.0 etiketlenebilir.**
