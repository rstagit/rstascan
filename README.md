# rstascan

اسکنر اتصال TLS/TCP نوشته‌شده با Go. به جای اینکه فقط چک کند پورت باز است یا نه، یک پکت واقعی TLS ClientHello می‌فرستد و منتظر پاسخ سرور می‌ماند.

روی Linux، macOS، ویندوز و Android (Termux) بدون هیچ وابستگی خارجی کار می‌کند.

گروه تلگرام برای پشتیبانی ، رفع اشکال
[rstasnispoof](https://t.me/rstasnispoof)
---

## چرا rstascan

اکثر اسکنرها فقط TCP handshake را چک می‌کنند. این ابزار یک قدم جلوتر می‌رود: یک TLS ClientHello کامل با SNI مشخص می‌سازد، به سرور می‌فرستد، و پاسخ را بررسی می‌کند. فرق بین این حالت‌ها را تشخیص می‌دهد:

سرور آنلاین است و TLS مشکلی ندارد
- سرور پاسخ می‌دهد ولی handshake را رد می‌کند
- پورت باز است ولی TLS کار نمی دهد
- هاست آفلاین  یا فیلتر است

---

## نصب

**پیش‌نیاز:** Go نسخه ۱.۱۸ به بالا

```bash
git clone https://github.com/rstagit/rstascan
cd rstascan
go run rstascan.go
```

یا بیلد مستقیم:

```bash
go build -o rstascan rstascan.go
./rstascan
```

**روی Termux:**
```bash
pkg install golang git
git clone https://github.com/rstagit/rstascan
cd rstascan
go run rstascan.go
```

نیازی به `go.mod` یا پکیج خارجی نیست.

---

## اجرا

```bash
go run rstascan.go
```

بعد از اجرا منوی تعاملی نمایش داده می‌شود:

```
  [1]  Single scan       اسکن یک آدرس (IP و/یا SNI)
  [2]  File scan         بارگذاری از فایل txt
  [3]  CIDR scan         اسکن رنج مثل 1.1.1.0/24
  [4]  IP range scan     اسکن از یک IP تا IP دیگر
  [5]  IP range + SNI    رنج IP همراه با تست TLS واقعی
  [6]  Settings          تنظیم timeout، workers، پورت
  [0]  Exit
```

---

## حالت‌های اسکن

### ۱ — اسکن تکی

انعطاف‌پذیرترین حالت. ترکیب‌های مختلف را پشتیبانی می‌کند:

| ورودی | رفتار |
|-------|-------|
| فقط IP | به IP وصل می‌شود، ClientHello با همان IP به عنوان SNI می‌فرستد |
| فقط SNI | ابتدا از طریق DNS آدرس را رزولو می‌کند، بعد تست می‌کند |
| IP + SNI | به IP وصل می‌شود، ClientHello با SNI داده‌شده می‌فرستد |

```
► IP address (or leave blank): 104.21.0.1
► SNI hostname (or leave blank): example.com
► Port [443]:
```

### ۲ — اسکن از فایل

یک فایل `.txt` می‌خواند. خطوط خالی و خطوطی که با `#` شروع می‌شوند نادیده گرفته می‌شوند. هر خط می‌تواند یکی از این فرمت‌ها باشد:

```
# فقط IP
1.2.3.4

# IP با پورت
1.2.3.4:8443

# IP و SNI با فاصله
1.2.3.4 example.com

# IP، SNI، پورت با ویرگول
1.2.3.4,example.com,443
```

### ۳ — اسکن CIDR

بلاک CIDR را باز می‌کند و همه هاست‌ها را تست می‌کند. SNI اختیاری است.

```
► CIDR (e.g. 1.1.1.0/24): 104.21.0.0/24
► SNI for all targets (optional): example.com
► Port [443]:
```

### ۴ — اسکن رنج IP

بدون نیاز به نوتاسیون CIDR، مستقیم از یک IP تا IP دیگر اسکن می‌کند.

```
► Start IP: 104.21.0.1
► End IP:   104.21.0.50
► Port [443]:
```

### ۵ — رنج IP + SNI

- مثل اسکن رنج، ولی برای هر IP یک TLS ClientHello واقعی با SNI مشخص می‌فرستد

```
► Start IP: 104.21.0.1
► End IP:   104.21.0.50
► SNI hostname (required): example.com
► Port [443]:
```

---

## نتایج

نتایج رنگ‌بندی شده و بر اساس وضعیت و latency مرتب می‌شوند:

```
  ✓ TLS    104.21.0.1:443       38ms   sni=example.com
  ✓ TLS    104.21.0.3:443       41ms   sni=example.com
  ~ ALERT  104.21.0.7:443       120ms
  ◎ TCP    104.21.0.9:443       55ms
  ✗ DEAD   104.21.0.2:443       connection refused
```

| نماد | معنی |
|------|------|
| `✓ TLS` | سرور با ServerHello جواب داد — handshake شروع شد |
| `~ ALERT` | سرور TLS Alert فرستاد، زنده است ولی hello را رد کرد |
| `◎ TCP` | TCP قبول شد ولی پاسخ TLS نبود |
| `✗ DEAD` | هیچ پاسخی نیامد یا connection refused |




---

## تنظیمات

از گزینه `6` در منو قابل تغییر است:

| تنظیم | پیش‌فرض | بازه |
|--------|---------|------|
| Timeout | 4 ثانیه | هر عدد مثبت |
| Workers | 16 | ۱ تا ۶۴ |
| Port | 443 | ۱ تا ۶۵۵۳۵ |

برای اسکن‌های بزرگ بالا بردن workers تا ۳۲ یا ۶۴ سرعت را به شکل محسوسی افزایش می‌دهد. روی شبکه‌های ضعیف‌تر کم کردن workers و زیاد کردن timeout دقت را بهتر می‌کند.

---

## متغیرهای محیطی

| متغیر | تأثیر |
|-------|-------|
| `NO_COLOR` | غیرفعال کردن رنگ‌ها |
| `FORCE_COLOR` | فعال کردن رنگ حتی روی pipe |

---

## مرتبط

- [rstaspoof](https://github.com/rstagit/rstaspoof) — پروکسی bypass DPI که این اسکنر در کنارش ساخته شد

---

## لایسنس

MIT
