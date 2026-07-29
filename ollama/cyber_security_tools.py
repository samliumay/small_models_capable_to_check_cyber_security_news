"""Siber güvenlik veri kaynakları ve Ollama araç şemaları."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urljoin
from xml.etree import ElementTree

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


USER_AGENT = "SiberGuvenlikAsistani/1.0"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _clamp(value: int, lower: int = 1, upper: int = 50) -> int:
    return max(lower, min(int(value), upper))


def _compact(value: Any, limit: int = 700) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


class CyberSecurityTools:
    """Harici kaynakları küçük, modele uygun JSON sonuçlarına dönüştürür."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        retry = Retry(
            total=2,
            connect=2,
            read=1,
            status=2,
            backoff_factor=3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self._news_cache: dict[tuple[str, int, int], tuple[float, dict[str, Any]]] = {}

    @property
    def schemas(self) -> list[dict[str, Any]]:
        return [
            self._schema(
                "siber_haberlerini_ara",
                "GDELT ve yapılandırılmışsa NewsAPI üzerinde güncel "
                "siber güvenlik haberlerini ara.",
                {
                    "sorgu": {
                        "type": "string",
                        "description": "Örn. ransomware, veri ihlali veya belirli bir şirket.",
                    },
                    "son_saat": {
                        "type": "integer",
                        "description": "Kaç saat geriye gidileceği (1-168).",
                        "default": 24,
                    },
                    "sonuc_sayisi": {
                        "type": "integer",
                        "description": "Döndürülecek en fazla sonuç (1-20).",
                        "default": 10,
                    },
                },
                ["sorgu"],
            ),
            self._schema(
                "son_cve_kayitlarini_getir",
                "NVD'den yakın zamanda yayımlanan CVE kayıtlarını getir; "
                "anahtar kelimeyle daraltılabilir.",
                {
                    "son_gun": {
                        "type": "integer",
                        "description": "Kaç gün geriye gidileceği (1-120).",
                        "default": 7,
                    },
                    "anahtar_kelime": {
                        "type": "string",
                        "description": "İsteğe bağlı ürün, üretici veya zafiyet anahtar kelimesi.",
                        "default": "",
                    },
                    "sonuc_sayisi": {
                        "type": "integer",
                        "description": "Döndürülecek en fazla sonuç (1-20).",
                        "default": 10,
                    },
                },
            ),
            self._schema(
                "cve_detayi_getir",
                "Bir CVE'yi NVD, CISA KEV ve yapılandırılmışsa OTX verileriyle ayrıntılandır.",
                {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE-2025-12345 biçimindeki kimlik.",
                    }
                },
                ["cve_id"],
            ),
            self._schema(
                "aktif_istismar_edilenleri_ara",
                "CISA Known Exploited Vulnerabilities (KEV) kataloğunda "
                "aktif istismar edilen CVE'leri ara.",
                {
                    "sorgu": {
                        "type": "string",
                        "description": "CVE, üretici veya ürün; boş bırakılırsa en yeni kayıtlar.",
                        "default": "",
                    },
                    "sonuc_sayisi": {
                        "type": "integer",
                        "description": "Döndürülecek en fazla sonuç (1-20).",
                        "default": 10,
                    },
                },
            ),
            self._schema(
                "guvenlik_duyurularini_getir",
                "CISA ve CERT/CC kaynaklarındaki en güncel güvenlik duyurularını getir.",
                {
                    "sonuc_sayisi": {
                        "type": "integer",
                        "description": "Her kaynaktan alınacak en fazla sonuç (1-20).",
                        "default": 8,
                    }
                },
            ),
            self._schema(
                "tehdit_istihbarati_ara",
                "Yapılandırılmış AlienVault OTX ve MISP kaynaklarında tehdit istihbaratı ara.",
                {
                    "sorgu": {
                        "type": "string",
                        "description": (
                            "Tehdit aktörü, zararlı yazılım, CVE, alan adı veya kampanya."
                        ),
                    },
                    "sonuc_sayisi": {
                        "type": "integer",
                        "description": "Döndürülecek en fazla sonuç (1-20).",
                        "default": 10,
                    },
                },
                ["sorgu"],
            ),
            self._schema(
                "mitre_attack_tekniklerini_ara",
                "MITRE ATT&CK Enterprise koleksiyonunda teknik adı, "
                "açıklaması veya kimliğiyle ara.",
                {
                    "sorgu": {
                        "type": "string",
                        "description": "Örn. phishing, credential dumping veya T1059.",
                    },
                    "sonuc_sayisi": {
                        "type": "integer",
                        "description": "Döndürülecek en fazla sonuç (1-20).",
                        "default": 10,
                    },
                },
                ["sorgu"],
            ),
        ]

    @property
    def available_functions(self) -> dict[str, Any]:
        return {
            "siber_haberlerini_ara": self.siber_haberlerini_ara,
            "son_cve_kayitlarini_getir": self.son_cve_kayitlarini_getir,
            "cve_detayi_getir": self.cve_detayi_getir,
            "aktif_istismar_edilenleri_ara": self.aktif_istismar_edilenleri_ara,
            "guvenlik_duyurularini_getir": self.guvenlik_duyurularini_getir,
            "tehdit_istihbarati_ara": self.tehdit_istihbarati_ara,
            "mitre_attack_tekniklerini_ara": self.mitre_attack_tekniklerini_ara,
        }

    @staticmethod
    def _schema(
        name: str,
        description: str,
        properties: dict[str, Any],
        required: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required or [],
                },
            },
        }

    @staticmethod
    def _default_timeout() -> tuple[int, int]:
        return (
            int(os.getenv("CYBER_API_CONNECT_TIMEOUT", "20")),
            int(os.getenv("CYBER_API_READ_TIMEOUT", "60")),
        )

    def _get(
        self, url: str, timeout: tuple[int, int] | None = None, **kwargs: Any
    ) -> requests.Response:
        response = self.session.get(
            url, timeout=timeout or self._default_timeout(), **kwargs
        )
        response.raise_for_status()
        return response

    def _post(self, url: str, **kwargs: Any) -> requests.Response:
        response = self.session.post(
            url, timeout=self._default_timeout(), **kwargs
        )
        response.raise_for_status()
        return response

    @staticmethod
    def _error(source: str, exc: Exception) -> dict[str, Any]:
        return {"kaynak": source, "hata": _compact(exc, 300)}

    def siber_haberlerini_ara(
        self, sorgu: str, son_saat: int = 24, sonuc_sayisi: int = 10
    ) -> dict[str, Any]:
        limit = _clamp(sonuc_sayisi, upper=20)
        hours = _clamp(son_saat, upper=168)
        query = sorgu.strip() or "cybersecurity"
        cache_key = (query.casefold(), hours, limit)
        cached = self._news_cache.get(cache_key)
        cache_seconds = int(os.getenv("CYBER_NEWS_CACHE_SECONDS", "300"))
        if cached and time.monotonic() - cached[0] < cache_seconds:
            return {**cached[1], "onbellekten": True}

        results: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        try:
            data = self._get(
                "https://api.gdeltproject.org/api/v2/doc/doc",
                timeout=(
                    int(os.getenv("GDELT_CONNECT_TIMEOUT", "30")),
                    int(os.getenv("GDELT_READ_TIMEOUT", "75")),
                ),
                params={
                    "query": query,
                    "mode": "ArtList",
                    "format": "json",
                    "maxrecords": limit,
                    "sort": "DateDesc",
                    "timespan": f"{hours}h",
                },
            ).json()
            for article in data.get("articles", [])[:limit]:
                results.append(
                    {
                        "kaynak": "GDELT",
                        "baslik": _compact(article.get("title"), 250),
                        "yayinci": article.get("domain"),
                        "tarih": article.get("seendate"),
                        "dil": article.get("language"),
                        "url": article.get("url"),
                    }
                )
        except (requests.RequestException, ValueError) as exc:
            errors.append(self._error("GDELT", exc))

        news_key = os.getenv("NEWSAPI_KEY")
        if news_key:
            try:
                data = self._get(
                    "https://newsapi.org/v2/everything",
                    headers={"X-Api-Key": news_key},
                    params={
                        "q": query,
                        "language": "en",
                        "sortBy": "publishedAt",
                        "pageSize": limit,
                    },
                ).json()
                if data.get("status") == "error":
                    raise ValueError(data.get("message", "NewsAPI hatası"))
                for article in data.get("articles", [])[:limit]:
                    results.append(
                        {
                            "kaynak": "NewsAPI",
                            "baslik": _compact(article.get("title"), 250),
                            "yayinci": (article.get("source") or {}).get("name"),
                            "tarih": article.get("publishedAt"),
                            "ozet": _compact(article.get("description"), 400),
                            "url": article.get("url"),
                        }
                    )
            except (requests.RequestException, ValueError) as exc:
                errors.append(self._error("NewsAPI", exc))

        results.sort(key=lambda item: item.get("tarih") or "", reverse=True)
        response_data = {
            "sorgu": query,
            "zaman_araligi_saat": hours,
            "sonuclar": results[:limit],
            "hatalar": errors,
            "not": None if news_key else "NEWSAPI_KEY tanımlı olmadığı için NewsAPI atlandı.",
        }
        if not results:
            response_data["alternatif_resmi_duyurular"] = self.guvenlik_duyurularini_getir(
                min(limit, 8)
            )
            response_data["uyari"] = (
                "Haber kaynakları sonuç vermedi. Aşağıdaki kayıtlar haber değil, "
                "CISA ve CERT/CC resmi güvenlik duyurularıdır."
            )
        else:
            self._news_cache[cache_key] = (time.monotonic(), response_data)
        return response_data

    def son_cve_kayitlarini_getir(
        self, son_gun: int = 7, anahtar_kelime: str = "", sonuc_sayisi: int = 10
    ) -> dict[str, Any]:
        days = _clamp(son_gun, upper=120)
        limit = _clamp(sonuc_sayisi, upper=20)
        end = datetime.now(UTC)
        start = end - timedelta(days=days)
        params: dict[str, Any] = {
            "pubStartDate": start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "pubEndDate": end.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "resultsPerPage": limit,
        }
        if anahtar_kelime.strip():
            params["keywordSearch"] = anahtar_kelime.strip()
        try:
            data = self._get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=self._nvd_headers(),
                params=params,
            ).json()
            return {
                "kaynak": "NVD",
                "sorgu_zamani_utc": end.isoformat(),
                "toplam_eslesme": data.get("totalResults", 0),
                "sonuclar": [
                    self._normalize_nvd(item.get("cve", {}))
                    for item in data.get("vulnerabilities", [])[:limit]
                ],
            }
        except (requests.RequestException, ValueError) as exc:
            return self._error("NVD", exc)

    def cve_detayi_getir(self, cve_id: str) -> dict[str, Any]:
        cve = cve_id.strip().upper()
        if not CVE_PATTERN.fullmatch(cve):
            return {"hata": "Geçersiz CVE kimliği.", "beklenen_bicim": "CVE-YYYY-NNNN"}
        result: dict[str, Any] = {"cve_id": cve}
        try:
            data = self._get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=self._nvd_headers(),
                params={"cveId": cve},
            ).json()
            items = data.get("vulnerabilities", [])
            result["nvd"] = (
                self._normalize_nvd(items[0].get("cve", {}))
                if items
                else {"bulundu": False}
            )
        except (requests.RequestException, ValueError) as exc:
            result["nvd"] = self._error("NVD", exc)

        kev = self.aktif_istismar_edilenleri_ara(cve, 1)
        result["cisa_kev"] = (kev.get("sonuclar") or [{"bulundu": False}])[0]

        otx_key = os.getenv("OTX_API_KEY")
        if otx_key:
            try:
                data = self._get(
                    f"https://otx.alienvault.com/api/v1/indicators/cve/{cve}/general",
                    headers={"X-OTX-API-KEY": otx_key},
                ).json()
                result["otx"] = {
                    "pulse_sayisi": (data.get("pulse_info") or {}).get("count", 0),
                    "pulses": [
                        {
                            "ad": _compact(pulse.get("name"), 250),
                            "olusturulma": pulse.get("created"),
                            "degistirilme": pulse.get("modified"),
                            "etiketler": pulse.get("tags", [])[:12],
                        }
                        for pulse in (data.get("pulse_info") or {}).get("pulses", [])[:5]
                    ],
                }
            except (requests.RequestException, ValueError) as exc:
                result["otx"] = self._error("AlienVault OTX", exc)
        else:
            result["otx"] = {"not": "OTX_API_KEY tanımlı değil; OTX sorgusu atlandı."}
        return result

    def aktif_istismar_edilenleri_ara(
        self, sorgu: str = "", sonuc_sayisi: int = 10
    ) -> dict[str, Any]:
        limit = _clamp(sonuc_sayisi, upper=20)
        try:
            data = self._get(
                "https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json"
            ).json()
            needle = sorgu.casefold().strip()
            matches = []
            for item in data.get("vulnerabilities", []):
                haystack = " ".join(
                    str(item.get(key, ""))
                    for key in ("cveID", "vendorProject", "product", "vulnerabilityName")
                ).casefold()
                if needle and needle not in haystack:
                    continue
                matches.append(
                    {
                        "cve_id": item.get("cveID"),
                        "uretici": item.get("vendorProject"),
                        "urun": item.get("product"),
                        "zafiyet": item.get("vulnerabilityName"),
                        "kataloga_eklenme": item.get("dateAdded"),
                        "aksiyon_son_tarihi": item.get("dueDate"),
                        "bilinen_fidye_yazilimi_kullanimi": item.get(
                            "knownRansomwareCampaignUse"
                        ),
                        "gerekli_aksiyon": _compact(item.get("requiredAction"), 400),
                        "notlar": _compact(item.get("notes"), 400),
                    }
                )
            matches.sort(key=lambda item: item.get("kataloga_eklenme") or "", reverse=True)
            return {
                "kaynak": "CISA KEV",
                "katalog_surumu": data.get("version"),
                "katalog_tarihi": data.get("dateReleased"),
                "sonuclar": matches[:limit],
            }
        except (requests.RequestException, ValueError) as exc:
            return self._error("CISA KEV", exc)

    def guvenlik_duyurularini_getir(self, sonuc_sayisi: int = 8) -> dict[str, Any]:
        limit = _clamp(sonuc_sayisi, upper=20)
        sources = [
            ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
            ("CERT/CC", "https://www.kb.cert.org/vuls/atomfeed/"),
        ]
        results: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for source, url in sources:
            try:
                root = ElementTree.fromstring(self._get(url).content)
                entries = root.findall(".//item") or root.findall(
                    ".//{http://www.w3.org/2005/Atom}entry"
                )
                for entry in entries[:limit]:
                    title = self._xml_text(entry, "title")
                    published = (
                        self._xml_text(entry, "pubDate")
                        or self._xml_text(entry, "updated")
                        or self._xml_text(entry, "published")
                    )
                    link = self._xml_text(entry, "link")
                    if not link:
                        link_node = entry.find("{http://www.w3.org/2005/Atom}link")
                        link = link_node.get("href") if link_node is not None else None
                    results.append(
                        {
                            "kaynak": source,
                            "baslik": _compact(title, 250),
                            "tarih": published,
                            "url": link,
                        }
                    )
            except (requests.RequestException, ElementTree.ParseError) as exc:
                errors.append(self._error(source, exc))
        return {"sonuclar": results, "hatalar": errors}

    def tehdit_istihbarati_ara(
        self, sorgu: str, sonuc_sayisi: int = 10
    ) -> dict[str, Any]:
        query = sorgu.strip()
        if not query:
            return {"hata": "Sorgu boş olamaz."}
        limit = _clamp(sonuc_sayisi, upper=20)
        results: dict[str, Any] = {}

        otx_key = os.getenv("OTX_API_KEY")
        if otx_key:
            try:
                data = self._get(
                    "https://otx.alienvault.com/api/v1/search/pulses",
                    headers={"X-OTX-API-KEY": otx_key},
                    params={"q": query, "sort": "modified", "limit": limit},
                ).json()
                results["otx"] = [
                    {
                        "id": item.get("id"),
                        "ad": _compact(item.get("name"), 250),
                        "aciklama": _compact(item.get("description"), 500),
                        "degistirilme": item.get("modified"),
                        "etiketler": item.get("tags", [])[:12],
                    }
                    for item in data.get("results", [])[:limit]
                ]
            except (requests.RequestException, ValueError) as exc:
                results["otx"] = self._error("AlienVault OTX", exc)
        else:
            results["otx"] = {"not": "OTX_API_KEY tanımlı değil."}

        misp_url, misp_key = os.getenv("MISP_BASE_URL"), os.getenv("MISP_API_KEY")
        if misp_url and misp_key:
            try:
                data = self._post(
                    urljoin(misp_url.rstrip("/") + "/", "events/restSearch"),
                    headers={
                        "Authorization": misp_key,
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                    json={
                        "returnFormat": "json",
                        "searchall": query,
                        "published": True,
                        "limit": limit,
                        "page": 1,
                    },
                    verify=os.getenv("MISP_VERIFY_TLS", "true").lower() != "false",
                ).json()
                events = data.get("response", data if isinstance(data, list) else [])
                results["misp"] = [
                    {
                        "id": (item.get("Event") or item).get("id"),
                        "bilgi": _compact((item.get("Event") or item).get("info"), 350),
                        "tarih": (item.get("Event") or item).get("date"),
                        "tehdit_seviyesi": (item.get("Event") or item).get(
                            "threat_level_id"
                        ),
                    }
                    for item in events[:limit]
                ]
            except (requests.RequestException, ValueError) as exc:
                results["misp"] = self._error("MISP", exc)
        else:
            results["misp"] = {
                "not": "MISP_BASE_URL ve MISP_API_KEY birlikte tanımlı değil."
            }
        return {"sorgu": query, "kaynaklar": results}

    def mitre_attack_tekniklerini_ara(
        self, sorgu: str, sonuc_sayisi: int = 10
    ) -> dict[str, Any]:
        query = sorgu.casefold().strip()
        if not query:
            return {"hata": "Sorgu boş olamaz."}
        limit = _clamp(sonuc_sayisi, upper=20)
        url = (
            "https://attack-taxii.mitre.org/api/v21/collections/"
            "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019/objects"
        )
        try:
            data = self._get(
                url,
                headers={"Accept": "application/taxii+json;version=2.1"},
                params={"match[type]": "attack-pattern"},
            ).json()
            matches = []
            for item in data.get("objects", []):
                external = (item.get("external_references") or [{}])[0]
                haystack = " ".join(
                    [
                        str(item.get("name", "")),
                        str(item.get("description", "")),
                        str(external.get("external_id", "")),
                    ]
                ).casefold()
                if query not in haystack:
                    continue
                matches.append(
                    {
                        "attack_id": external.get("external_id"),
                        "ad": item.get("name"),
                        "aciklama": _compact(item.get("description"), 600),
                        "platformlar": item.get("x_mitre_platforms", []),
                        "url": external.get("url"),
                    }
                )
                if len(matches) >= limit:
                    break
            return {"kaynak": "MITRE ATT&CK TAXII 2.1", "sonuclar": matches}
        except (requests.RequestException, ValueError) as exc:
            return self._error("MITRE ATT&CK", exc)

    @staticmethod
    def _xml_text(entry: ElementTree.Element, name: str) -> str | None:
        node = entry.find(name)
        if node is None:
            node = entry.find(f"{{http://www.w3.org/2005/Atom}}{name}")
        return node.text.strip() if node is not None and node.text else None

    @staticmethod
    def _nvd_headers() -> dict[str, str]:
        key = os.getenv("NVD_API_KEY")
        return {"apiKey": key} if key else {}

    @staticmethod
    def _normalize_nvd(cve: dict[str, Any]) -> dict[str, Any]:
        descriptions = cve.get("descriptions", [])
        description = next(
            (item.get("value") for item in descriptions if item.get("lang") == "en"),
            descriptions[0].get("value") if descriptions else "",
        )
        metrics = cve.get("metrics", {})
        metric = next(
            (
                entries[0]
                for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
                if (entries := metrics.get(name))
            ),
            {},
        )
        cvss = metric.get("cvssData", {})
        weaknesses = [
            desc.get("value")
            for weakness in cve.get("weaknesses", [])
            for desc in weakness.get("description", [])
            if desc.get("lang") == "en"
        ]
        references = [
            {"url": ref.get("url"), "etiketler": ref.get("tags", [])}
            for ref in cve.get("references", [])[:8]
        ]
        return {
            "cve_id": cve.get("id"),
            "yayim_tarihi": cve.get("published"),
            "degistirilme_tarihi": cve.get("lastModified"),
            "durum": cve.get("vulnStatus"),
            "aciklama": _compact(description, 900),
            "cvss_puani": cvss.get("baseScore"),
            "cvss_seviyesi": cvss.get("baseSeverity") or metric.get("baseSeverity"),
            "cvss_vektoru": cvss.get("vectorString"),
            "cwe": list(dict.fromkeys(filter(None, weaknesses)))[:8],
            "referanslar": references,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
        }

    def execute(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        function = self.available_functions.get(name)
        if not function:
            return {"hata": f"Bilinmeyen araç: {name}"}
        try:
            return function(**arguments)
        except TypeError as exc:
            return {"hata": "Araç parametreleri geçersiz.", "ayrinti": _compact(exc, 300)}
        except Exception as exc:  # Aracın bir hatası ajan döngüsünü sonlandırmamalı.
            return {
                "hata": "Araç çalıştırılırken beklenmeyen hata oluştu.",
                "ayrinti": _compact(exc, 300),
            }

    @staticmethod
    def to_json(result: dict[str, Any]) -> str:
        return json.dumps(result, ensure_ascii=False, default=str)
