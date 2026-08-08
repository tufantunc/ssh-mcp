# ssh-mcp v2 — Yayına Hazırlık Raporu

> İlk sürüm: 2026-08-08 · **Güncellendi: 2026-08-08 (düzeltmeler sonrası)**
> Branch: `v2` (main'e göre 74 commit)
> Yöntem: build + test çalıştırma, 8 uzman kod incelemesi (security, correctness, backend, tests, performance, craft, ai-antipatterns, api-contract), açık issue/PR eşlemesi, ardından bulguların düzeltilmesi ve her düzeltmenin testle doğrulanması.

---

## 1. Özet Karar

**Verdict: APPROVE (koşullu) — gerçek sunucuda manuel doğrulama turundan sonra 2.0.0 etiketlenebilir.**

İlk incelemede yayını bloke eden 9 madde ve 12 yüksek öncelikli madde vardı. **Tamamı kapatıldı.** Ek olarak, düzeltme sürecinde ilk incelemenin bulamadığı 5 hata daha ortaya çıktı (aşağıda ⚡ ile işaretli) — çünkü test kapsamı eklenene kadar görünür değillerdi.

| Ölçüt | İlk durum | Şimdi |
|---|---|---|
| Test sayısı | 183 | **321** (6'sı Windows host'u gerektirdiği için opt-in) |
| Suite durumu | 182/183 (1 kırmızı) | **315/315**, ardışık koşularda kararlı |
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
| `npm test` | ✅ **315/315** + 6 opt-in Windows testi (39 dosya) |
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
| ⚡ **busybox ash'te her session açılışı 3 sn sürüyordu** | Prompt tespiti ham buffer'ı test ediyordu; ash prompt'undan sonra ANSI imleç sorgusu (`ESC[6n`) yolluyor, eşleşme kaçıyor ve 3 sn'lik tavana düşülüyordu | Alpine/ash imajı eklenince |
| ⚡ **Windows'ta interactive session 60 sn sessizce timeout oluyordu** | cmd.exe kanalı kabul ediyor ve `>` prompt'u gösteriyor, yani açılış *başarılı görünüyordu*; sonra her komut tam timeout süresi bekleyip "timed out" diyordu. Artık handshake açılışta başarısız oluyor ve nedenini söylüyor (5 sn) | Gerçek Windows host'una bağlanınca |
| ⚡ **Dropbear host'larında session/SFTP açılışı yazı-tura** | Dropbear, bir önceki kanal serbest bırakıldıktan hemen sonra kanal açmayı aralıklı reddediyor; SFTP trafiği altında bağlantıyı tamamen düşürüyor. Ham ssh2 ile de üretildi — bizim kodumuz değil, ama araçlarımızı o host sınıfında güvenilmez kılıyordu | Dropbear imajı eklenince |

---

## 4. Kalan İş (yayını bloke etmez)

| Madde | Durum |
|---|---|
| PR #60-#63 WebUI | v2.1'e ertelendi |
| PR #64 config hot-reload | v2.1'e ertelendi. `SessionManager` ve `CommandQuota` artık profili çağrı anında okuyor — gereken şekil hazır |
| Issue #27 "description sonrası çıktı yok" | ❓ v2'de `description` parametresi kaldırıldı; senaryo net değil, manuel doğrulama gerekli |

`docs/v2-remaining-work.md`'deki 9 maddenin tamamı sonuçlandı: 4'ü tamamlandı
(OTEL, changesets, komut kotası, JIT approval), 4'ü gerekçesiyle iptal edildi
(asciinema, age config, dynamic connections, sigstore), WebUI ertelendi.

Kod yapısı tarafında bu turda kapatılanlar: `SessionManager` çıkarıldı
(`SSHConnection` 464 → 374 satır), `tools/registry.ts` konuya göre bölündü
(704 satır → en büyüğü 267), `noUnusedLocals`/`noUnusedParameters` açıldı.

### Test altyapısı hakkında bilinen kısıt

`vitest.config.ts`'te `fileParallelism: false` **gerekli**. Paralellik açıkken entegrasyon dosyaları eşzamanlı SSH handshake sayısını katlıyor ve bağlantılar handshake öncesi düşüyor — testler hem hata veriyor hem de *sessizce atlanıyor*. Ölçüldü: paralellikle 2 hata/4 atlanan ile başlayıp ikinci koşuda dosya dosya çöküyor; serileştirilmiş halde 8 ardışık koşu temiz. Süre farkı yok (~24 sn).

Bu yerel macOS/Docker Desktop port yönlendirme katmanının bir özelliği (sshd hiçbir şey loglamıyor, ham TCP sorunsuz, ~30 sn'de kendiliğinden düzeliyor) ve aynı desen düzeltmeler öncesi baseline'da da görüldü. CI Linux'ta service container'larla doğrudan ağ kullandığı için oraya yansıması beklenmiyor — **ama bu doğrulanmadı.**

---

## 5. Gerçek Sunucuda Doğrulama

İlk rapor bu bölümü 12 maddelik **manuel** bir liste olarak yazmıştı. O sırada
handler katmanının hiç testi yoktu. Artık `test/e2e/` altında derlenmiş sunucuyu
**gerçek stdio/HTTP transport** üzerinden **gerçek MCP SDK client**'ı ile sürüp
Docker'daki gerçek SSH sunucularına bağlayan bir suite var — hiçbir şey mock'lu
değil. §5'in 9 maddesi artık her koşuda otomatik doğrulanıyor.

### Otomatikleşenler (`npm run test:e2e`)

| Madde | Nerede |
|---|---|
| 11 tool'un tamamı gerçek client ile | `e2e/tools.e2e.test.ts` |
| Onay akışı: prompt geliyor, red komutu durduruyor (dosya hâlâ yerinde) | `e2e/approval.e2e.test.ts` |
| Başarısız komut → istemci exit code ve stderr görüyor | `e2e/tools.e2e.test.ts` |
| `read-command` + `curl` reddi | `e2e/tools.e2e.test.ts` |
| `[defaults]` cascade'i gerçek config yüklemesiyle (`ask-all`, `deny`, kota, JIT grant) | `e2e/approval.e2e.test.ts` |
| HTTP: iki eşzamanlı istemci, biri ayrılınca üçüncü bağlanabiliyor | `e2e/http.e2e.test.ts` |
| `/health` tokensiz, `/status` tokenli | `e2e/http.e2e.test.ts` |
| TOFU kaydı, bozuk fingerprint reddi, strict mod | `integration/host-key.test.ts` |
| **Farklı kabuk (Alpine + busybox ash) ve farklı sshd (Dropbear)**: algoritma anlaşması, session protokolü, CWD/env, exit code, priming, SFTP | `integration/shell-compat.test.ts` |
| ProxyJump kopma + yeniden bağlanma | `integration/proxy-jump.test.ts` |
| **pnpm (katı çözümleyici) altında OTEL zinciri çözülüyor** | `e2e/packaging.e2e.test.ts` |
| Kaldırılan v1 flag'leri startup'ta reddediliyor | `e2e/packaging.e2e.test.ts` |

pnpm testi H11'in gerçek doğrulaması: `@opentelemetry/resources` ve
`semantic-conventions` önceden yalnızca npm hoisting sayesinde çözülüyordu, yani
yayınlanan paketi pnpm/yarn-pnp ile kuran birinde tracing çalışma anında
kırılırdı.

### Windows desteği — ölçülen gerçek

README kayıtsız şartsız "Windows desteği" diyordu. Gerçek bir host'a karşı
ölçüldüğünde destek **kısmi**:

| | Linux/BSD/macOS | Windows OpenSSH |
|---|:---:|:---:|
| exec araçları, SFTP, background session | ✅ | ✅ |
| **interactive session** | ✅ | ❌ |

Sebep düzeltilebilir bir hata değil, protokolün doğası: session protokolü
komutları `printf` işaretçileriyle çevreliyor ve `$?`/`$PWD` okuyor — cmd.exe'de
bunların hiçbiri yok. PowerShell'i `DefaultShell` yapmak da çözmez; protokol
POSIX'e özgü, sadece "cmd değil"e değil. README bu tabloyla güncellendi.

### Docker'ın veremediği — kalan gerçek manuel liste (2 madde)

- [ ] **Claude Desktop'ta bir destructive komut çalıştırıp onay prompt'unu görmek.**
      Protokolü test edebiliyoruz, istemcinin prompt'u gerçekten gösterip
      göstermediğini edemiyoruz. Kritik: istemci elicitation desteklemiyorsa
      sunucu fail-closed davranıp **her destructive komutu reddeder** — ürün
      "bozuk" görünür. B7'de bunun için stderr log'u eklendi, bir kez gözle
      görülmeli.
- [x] ~~**Windows OpenSSH.**~~ **Yapıldı** — gerçek bir Windows 11 host'una
      (build 26200, UTM VM) karşı test edildi. `integration/windows-compat.test.ts`,
      `SSH_MCP_WIN_HOST/_USER/_PASSWORD` ile opt-in. Sonuç: destek gerçek ama
      **kısmi** — exec araçları, background session'lar ve SFTP çalışıyor;
      interactive session'lar çalışamaz (aşağıya bakın). Eski OpenSSH 7.x hâlâ
      denenmedi.
- [ ] **CI'ı bir kez Linux'ta yeşil görmek** (`SSH_MCP_REQUIRE_SERVERS=1` ile).

Bunların dışında gerçek ağ koşulları (NAT/firewall idle timeout — `keepalive`'ın
var olma sebebi) Docker loopback'te hiç oluşmuyor; bu bilinen bir kapsam boşluğu.

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
