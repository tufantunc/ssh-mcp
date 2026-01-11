# Claude Code ile SSH MCP Kullanımı - Detaylı Rehber

## 1. Kurulum Seçenekleri

### Seçenek A: NPX ile (Önerilen - En Kolay)

```bash
claude mcp add --transport stdio ssh-mcp -- npx -y ssh-mcp -- --host=vm1.example.com --port=2222 --user=root --key=C:/Users/user/.ssh/id_ed25519
```

**Avantajları:**
- Her zaman son versiyonu kullanır
- Build gerektirmez
- Kolay kurulum

### Yöntem 2: Lokal Build

```bash
# Önce projeyi build edin
cd C:/Users/user/source/mcp-stuff/ssh-mcp
npm run build

# Sonra Claude'a ekleyin
claude mcp add --transport stdio ssh-mcp-local -- \
  node C:/Users/user/source/mcp-stuff/ssh-mcp/build/index.js \
  --host=vm1.example.com \
  --port=2222 \
  --user=root \
  --key=C:/Users/user/.ssh/id_ed25519
```

### Yöntem 3: Docker ile

```bash
claude mcp add --transport stdio ssh-mcp-docker -- \
  docker run -i --rm --network host \
  -v C:/Users/user/.ssh/id_ed25519:/root/.ssh/id_ed25519:ro \
  ssh-mcp:latest \
  --host=vm1.example.com \
  --port=2222 \
  --user=root \
  --key=/root/.ssh/id_ed25519
```

---

## 2. Claude Code'da Çoklu Host Kullanımı

### 🎯 Önemli: İlk default sunucu (vm1.example.com) ile başlarsınız, sonra diğer sunuculara dinamik olarak bağlanırsınız!

### Senaryo 1: Yeni Sunucuya İlk Bağlantı

**Siz Claude Code'da yazın:**
```
vm2.example.com sunucusuna bağlan ve disk kullanımını göster.

Sunucu bilgileri:
- Host: vm2.example.com
- Port: 2222
- User: root
- SSH Key: Aynı key'i kullan (C:/Users/user/.ssh/id_ed25519)
```

**Claude'un yapacağı:**
```json
{
  "tool": "exec",
  "command": "df -h",
  "description": "Check disk usage on vm2.example.com",
  "host": "vm2.example.com:2222"
}
```

---

### Örnek Konuşma 2: Üç sunucuya paralel komut

**Siz:**
```
vm1.example.com, vm2.example.com ve vm3.example.com sunucularına aynı anda bağlan ve uptime göster.

Bilgiler (hepsi aynı):
- Port: 2222
- User: root
- SSH Key: mevcut key'i kullan
```

**Claude:**
```
Üç sunucuya paralel olarak uptime komutunu gönderiyorum...
```

Claude otomatik olarak şu komutları paralel çalıştırır:
- vm1.example.com:2222'e bağlan
- vm2.example.com:2222'e bağlan
- vm3.example.com:2222'e bağlan

---

## Quick Start Komutlar

### 1. NPX ile Kurulum (En Kolay):

```bash
claude mcp add --transport stdio ssh-mcp -- npx -y ssh-mcp -- --host=vm1.example.com --port=2222 --user=root --key=C:/Users/user/.ssh/id_ed25519
```

### 2. Lokal Build ile Kurulum:

```bash
cd C:/Users/user/source/mcp-stuff/ssh-mcp
npm run build

claude mcp add --transport stdio ssh-mcp-local -- node C:/Users/user/source/mcp-stuff/ssh-mcp/build/index.js -- --host=vm1.example.com --port=2222 --user=root --key=C:/Users/user/.ssh/id_ed25519
```

### 3. Docker ile Kurulum:

```bash
claude mcp add --transport stdio ssh-mcp-docker -- docker run -i --rm --network host -v C:/Users/user/.ssh/id_ed25519:/root/.ssh/id_ed25519:ro ssh-mcp:latest -- --host=vm1.example.com --port=2222 --user=root --key=/root/.ssh/id_ed25519
```

---

## Claude Code'da Canlı Kullanım Örnekleri

### Örnek 1: İlk kullanım (default host)

**Siz:**
```
vm1.example.com sunucusunda disk kullanımını göster
```

**Claude otomatik çalıştırır:**
```
exec tool: df -h
```

---

### Örnek 2: Farklı sunucuya bağlanma

**Siz:**
```
vm2.example.com sunucusuna bağlan ve uptime göster.

Sunucu bilgileri:
- Host: vm2.example.com
- Port: 2222 (default)
- User: root
- SSH Key: aynı key dosyası
```

**Claude anlar ve çalıştırır:**
```javascript
exec({
  command: "uptime",
  host: "vm2.example.com:2222"
})
```

---

## Claude Code'da Kullanım Örnekleri

### Örnek 1: İlk kurulum

```bash
# NPX ile (önerilen - her zaman son versiyonu kullanır)
claude mcp add --transport stdio ssh-mcp -- npx -y ssh-mcp -- --host=vm1.example.com --port=2222 --user=root --key=C:/Users/user/.ssh/id_ed25519

# Lokal build ile
claude mcp add --transport stdio ssh-mcp -- node C:/Users/user/source/mcp-stuff/ssh-mcp/build/index.js -- --host=vm1.example.com --port=2222 --user=root --key=C:/Users/user/.ssh/id_ed25519

# Docker ile
claude mcp add --transport stdio ssh-mcp -- docker run -i --rm --network host -v C:/Users/user/.ssh/id_ed25519:/root/.ssh/id_ed25519:ro ssh-mcp:latest -- --host=vm1.example.com --port=2222 --user=root --key=/root/.ssh/id_ed25519
```

## Claude Code'da Çoklu Host Kullanımı

MCP server kurulduktan sonra, Claude Code'da normal konuşma ile farklı sunuculara bağlanabilirsiniz:

### Örnek 1: İlk bağlantı (Default host)

**Siz:**
```
vm1.example.com sunucusunda disk kullanımını göster
```

**Claude çalıştırır:**
```
Tool: exec
Command: df -h
```

---

### Örnek 2: Farklı sunucuya bağlanma

**Siz:**
```
vm2.example.com sunucusuna bağlan ve uptime komutunu çalıştır.
Port: 2222
User: root
SSH Key: Aynı key (C:/Users/user/.ssh/id_ed25519)
```

**Claude otomatik olarak:**
```json
{
  "tool": "exec",
  "command": "uptime",
  "host": "vm2.example.com:2222"
}
```

---

### Örnek: 3 Sunucuya Paralel Komut

**Siz Claude Code'da:**
```
vm1.example.com, vm2.example.com ve vm3.example.com sunucularında aynı anda disk kullanımını kontrol et.

Tüm sunucular için:
- Port: 2222
- User: root
- SSH Key: C:/Users/user/.ssh/id_ed25519
```

**Claude paralel çalıştırır:**
- vm1.example.com:2222 → `df -h`
- vm2.example.com:2222 → `df -h`
- vm3.example.com:2222 → `df -h`

---

## Kurulum Komutları

### NPX ile (Önerilen):
```bash
claude mcp add --transport stdio ssh-mcp-local -- \
  npx -y ssh-mcp -- \
  --host=vm1.example.com \
  --port=2222 \
  --user=root \
  --key=C:/Users/user/.ssh/id_ed25519
```

### Build edilmiş versiyon ile:
```bash
cd C:/Users/user/source/mcp-stuff/ssh-mcp
npm run build

claude mcp add --transport stdio ssh-mcp-local -- \
  node C:/Users/user/source/mcp-stuff/ssh-mcp/build/index.js -- \
  --host=vm1.example.com \
  --port=2222 \
  --user=root \
  --key=C:/Users/user/.ssh/id_ed25519
```

### Docker ile:
```bash
claude mcp add --transport stdio ssh-mcp-docker -- \
  docker run -i --rm --network host \
  -v C:/Users/user/.ssh/id_ed25519:/root/.ssh/id_ed25519:ro \
  ssh-mcp:latest -- \
  --host=vm1.example.com \
  --port=2222 \
  --user=root \
  --key=/root/.ssh/id_ed25519
```

Şimdi size komutları ve pratik örnekleri vereceğim:

## 🚀 KURULUM KOMUTLARI

### 1. NPX ile Kurulum (En Basit - Önerilen)

```bash
claude mcp add --transport stdio ssh-mcp -- npx -y ssh-mcp -- --host=vm1.example.com --port=2222 --user=root --key=C:/Users/user/.ssh/id_ed25519
```

### 2. Build Edilmiş ile Kurulum

```bash
# Önce build edin
cd C:/Users/user/source/mcp-stuff/ssh-mcp
npm run build

# Sonra ekleyin
claude mcp add --transport stdio ssh-mcp -- node C:/Users/user/source/mcp-stuff/ssh-mcp/build/index.js -- --host=vm1.example.com --port=2222 --user=root --key=C:/Users/user/.ssh/id_ed25519
```

### 3. Docker ile Kurulum

```bash
claude mcp add --transport stdio ssh-mcp -- docker run -i --rm --network host -v C:/Users/user/.ssh/id_ed25519:/root/.ssh/id_ed25519:ro ssh-mcp:latest -- --host=vm1.example.com --port=2222 --user=root --key=/root/.ssh/id_ed25519
```

---

## 💬 CLAUDE CODE'DA KULLANIM ÖRNEKLERİ

### Örnek 1: İlk Bağlantı (Default Host)

**Siz:**
```
vm1.example.com sunucusunda /var/log dosyalarını listele
```

**Claude otomatik çalıştırır:**
- Default host (vm1.example.com:2222) kullanılır

---

### Örnek 2: Farklı Sunucuya Bağlanma

**Siz:**
```
vm2.example.com sunucusuna bağlan ve disk kullanımını göster.

Sunucu: vm2.example.com
Port: 2222
User: root
Key: C:/Users/user/.ssh/id_ed25519
```

**Claude otomatik yapar:**
```json
{
  "tool": "exec",
  "command": "df -h",
  "host": "vm2.example.com:2222"
}
```

---

### Örnek 3: Çoklu Sunucu (vm1, vm2, vm3)

**Siz:**
```
vm1.example.com, vm2.example.com ve vm3.example.com sunucularında uptime komutunu çalıştır.

Tüm sunucular:
- Port: 2222
- User: root
- SSH Key: C:/Users/user/.ssh/id_ed25519
```

**Claude paralel çalıştırır:**
```json
[
  { "tool": "exec", "command": "uptime", "host": "vm1.example.com:2222" },
  { "tool": "exec", "command": "uptime", "host": "vm2.example.com:2222" },
  { "tool": "exec", "command": "uptime", "host": "vm3.example.com:2222" }
]
```

---

### Örnek 4: Hangi Sunuculara Bağlıyım?

**Siz:**
```
Hangi sunuculara bağlantım var?
```

**Claude:**
```json
{ "tool": "list-hosts" }
```

**Çıktı örneği:**
```
root@vm1.example.com:2222 (connected)
root@vm2.example.com:2222 (connected)
root@vm1.example.com:2222 (connected)
root@vm2.example.com:2222 (connected)
root@vm3.example.com:2222 (connected)
```

---

### Örnek 5: Tüm Sunucularda Sistem Kontrolü

**Siz:**
```
vm1, vm2, vm3, vm4, vm5 tüm sunucularda şu kontrolleri yap:
1. Disk kullanımı (df -h)
2. Memory kullanımı (free -h)
3. CPU kullanımı (top -bn1 | head -15)

Sunucu bilgileri:
- Host: {vm1,vm2,vm3,vm4,vm5}.example.com
- Port: 2222
- User: root
- Key: C:/Users/user/.ssh/id_ed25519
```

**Claude her sunucu için çalıştırır:**
```bash
df -h && echo "---" && free -h && echo "---" && top -bn1 | head -15
```

---

### Örnek 6: Log Analizi

**Siz:**
```
vm1, vm2, vm3 sunucularında nginx error loglarında "500" hatalarını ara ve say.

Sunucular: vm1.example.com, vm2.example.com, vm3.example.com
Port: 2222
User: root
Key: C:/Users/user/.ssh/id_ed25519
```

**Claude:**
```bash
grep "500" /var/log/nginx/error.log | wc -l
```

---

### Örnek 7: Docker Container Kontrolü

**Siz:**
```
Tüm production sunucularında (vm1, vm2) çalışan docker container'ları listele.

Sunucular: vm2.example.com, vm1.example.com
Port: 2222
```

**Claude:**
```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

---

## 📋 PRATİK ŞABLONLAR

### Şablon 1: Tek Sunucu
```
[SUNUCU].example.com sunucusunda [KOMUT] çalıştır

Sunucu: [SUNUCU].example.com
Port: 2222
User: root
Key: C:/Users/user/.ssh/id_ed25519
```

### Şablon 2: Çoklu Sunucu
```
[vm1,vm2,vm3].example.com sunucularında [KOMUT] çalıştır

Port: 2222
User: root
Key: C:/Users/user/.ssh/id_ed25519
```

### Şablon 3: Tüm Sunucular
```
Tüm sunucularda (vm1, vm2, vm3, vm4, vm5) [İŞLEM] yap

Port: 2222, User: root, Key: C:/Users/user/.ssh/id_ed25519
```

---

## ✅ ÖZET

1. **Kurulum:** Tek komutla claude mcp add
2. **Default host:** vm1.example.com:2222 (otomatik)
3. **Diğer hostlar:** Prompt'ta belirtin (vm2.example.com, vm1.example.com, etc.)
4. **Format:** `host: "sunucu.example.com:port"` veya sadece `host: "sunucu.example.com"`
5. **list-hosts:** Aktif bağlantıları gösterir

Hangi kurulum yöntemini tercih edersiniz? NPX en kolay olanıdır!