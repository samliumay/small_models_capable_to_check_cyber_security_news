---
title: Siber Güvenlik Haber Asistanı
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: gradio
sdk_version: 6.20.0
app_file: app.py
python_version: "3.11"
fullWidth: true
short_description: Ollama ve araç çağrılarıyla güncel CVE ve siber güvenlik haberleri
tags:
  - ollama
  - cybersecurity
  - tool-calling
  - cve
  - turkish
---

# Siber Güvenlik Haber Asistanı

Yerel bir Ollama modelinin güncel siber güvenlik kaynaklarını araç çağrılarıyla
sorguladığı Türkçe Gradio uygulaması. Arayüz; modelin çağırdığı aracı,
parametrelerini, dönen sonucu, tur numarasını ve nihai yanıtı ayrı ayrı gösterir.
Modelin gizli düşünce metni gösterilmez.

## Veri kaynakları

Anahtarsız kullanılabilen kaynaklar:

- GDELT — güncel haber araması
- CISA KEV — aktif istismar edildiği bilinen zafiyetler
- NIST NVD — CVE arama ve ayrıntıları
- CISA RSS ve CERT/CC Atom — resmi güvenlik duyuruları
- MITRE ATT&CK TAXII 2.1 — Enterprise teknikleri

İsteğe bağlı kaynaklar:

- NewsAPI (`NEWSAPI_KEY`)
- AlienVault OTX (`OTX_API_KEY`)
- NVD yüksek istek limiti (`NVD_API_KEY`)
- Kurumsal MISP (`MISP_BASE_URL`, `MISP_API_KEY`)

API anahtarları hiçbir zaman kaynak koda veya model mesajına eklenmez; yalnızca
sunucu tarafındaki ortam değişkenlerinden okunur.

## Yerel çalıştırma

Gereksinimler:

- Python 3.11+
- Çalışan bir [Ollama](https://docs.ollama.com/) sunucusu
- Araç çağrısını destekleyen bir Ollama modeli

```bash
ollama serve
ollama pull qwen3.6:latest
cp .env.example .env
uv sync
uv run python app.py
```

`uv` kullanmıyorsanız:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Uygulama varsayılan olarak `http://127.0.0.1:11434` ve
`qwen3.6:latest` kullanır. Ayarlar kabuktan verilebilir:

```bash
export OLLAMA_MODEL=qwen3.6:latest
export NEWSAPI_KEY=...
export NVD_API_KEY=...
python app.py
```

`.env` dosyası örnek amaçlıdır; Python uygulaması bu dosyayı kendiliğinden
yüklemez. Değerleri kabuğa aktarın veya dağıtım platformunun secret yönetimini
kullanın.

## Çalışma biçimi

Örnek soru:

> Son 7 günde yayımlanan kritik CVE'leri bul ve aktif istismar durumlarını kontrol et.

Beklenen akış:

1. Model `son_cve_kayitlarini_getir` aracını çağırır.
2. Dönen CVE'lerden gerekli gördükleri için `cve_detayi_getir` veya
   `aktif_istismar_edilenleri_ara` çağrısını yapar.
3. Arayüz her çağrıyı ve sonucu tur bazında gösterir.
4. Model, tarih ve kaynak bağlantıları içeren Türkçe nihai yanıtı üretir.

Model en fazla altı araç turu çalıştırabilir. Bu sınır hatalı veya sonsuz araç
döngülerini engeller.

## Yapılandırma

| Değişken | Varsayılan | Açıklama |
|---|---:|---|
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama veya uyumlu güvenli geçit |
| `OLLAMA_MODEL` | `qwen3.6:latest` | Kullanılacak model |
| `OLLAMA_API_KEY` | boş | Uzak geçit için Bearer anahtarı |
| `OLLAMA_TIMEOUT_SECONDS` | `300` | Model yanıt zaman aşımı |
| `OLLAMA_NUM_CTX` | `16384` | Bağlam penceresi |
| `OLLAMA_TEMPERATURE` | `0.2` | Üretim sıcaklığı |
| `CYBER_API_CONNECT_TIMEOUT` | `20` | Genel API bağlantı zaman aşımı |
| `CYBER_API_READ_TIMEOUT` | `60` | Genel API okuma zaman aşımı |
| `GDELT_CONNECT_TIMEOUT` | `30` | GDELT için bağlantı zaman aşımı |
| `GDELT_READ_TIMEOUT` | `75` | GDELT için okuma zaman aşımı |
| `CYBER_NEWS_CACHE_SECONDS` | `300` | Aynı haber sorgusunun önbellek süresi |
| `NEWSAPI_KEY` | boş | NewsAPI erişimi |
| `NVD_API_KEY` | boş | Daha yüksek NVD istek limiti |
| `OTX_API_KEY` | boş | AlienVault OTX erişimi |
| `MISP_BASE_URL` | boş | Kurumsal MISP kök adresi |
| `MISP_API_KEY` | boş | MISP erişim anahtarı |
| `MISP_VERIFY_TLS` | `true` | MISP TLS sertifika doğrulaması |

## Hugging Face Spaces

Bu depo Gradio Space dosya düzenine hazırdır. Ancak standart bir Space,
bilgisayarınızdaki yerel Ollama’ya erişemez. İki dağıtım seçeneği vardır:

1. **Uzak Ollama geçidi:** Space secret ayarlarına `OLLAMA_BASE_URL`,
   `OLLAMA_API_KEY` ve gerekli haber API anahtarlarını ekleyin. Ollama’yı doğrudan
   internete açmayın; TLS ve kimlik doğrulama kullanan bir geçit arkasına koyun.
2. **Docker/GPU Space:** Ollama ve modeli aynı Docker Space içinde çalıştırın.
   `qwen3.6:latest` yaklaşık 23 GB olduğundan uygun GPU belleği, disk alanı ve
   başlangıç süresi gerekir. Bu depo henüz bu donanım seçeneğini zorunlu kılmaz.

Uzak geçit hazır olduğunda Space oluşturma ve yükleme örneği:

```bash
hf auth login
hf repos create KULLANICI_ADI/siber-guvenlik-asistani --repo-type space --space-sdk gradio
git remote add space https://huggingface.co/spaces/KULLANICI_ADI/siber-guvenlik-asistani
git push space main
```

Space secret değerlerini Hugging Face web arayüzündeki **Settings → Variables and
secrets** bölümünden ekleyin. Her push sonrasında Space otomatik olarak yeniden
oluşturulur.

## Testler

```bash
python -m unittest discover -s tests -v
```

Testler gerçek API veya Ollama bağlantısı kurmadan araç şemalarını, CVE
normalizasyonunu ve çok turlu araç döngüsünü doğrular.

## Güvenlik ve doğruluk

- Uygulama savunma ve haber analizi amaçlıdır.
- Güncel veri kaynakları gecikebilir veya geçici olarak hata verebilir.
- CVSS puanı tek başına aktif istismar kanıtı değildir; KEV durumu ayrıca gösterilir.
- Kritik operasyonel kararlar özgün CISA, NVD, CERT/CC veya üretici duyurusundan
  doğrulanmalıdır.
