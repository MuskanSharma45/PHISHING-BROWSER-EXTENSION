"""
Feature extraction from a live URL for real-time prediction.
Extracts all 87 features matching dataset_phishing.csv columns.
Must stay in sync with ml/feature_extractor.py
"""

import re
from urllib.parse import urlparse

FEATURE_COLS = [
    "length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens",
    "nb_at", "nb_qm", "nb_and", "nb_or", "nb_eq", "nb_underscore",
    "nb_tilde", "nb_percent", "nb_slash", "nb_star", "nb_colon",
    "nb_comma", "nb_semicolumn", "nb_dollar", "nb_space", "nb_www",
    "nb_com", "nb_dslash", "http_in_path", "https_token",
    "ratio_digits_url", "ratio_digits_host", "punycode", "port",
    "tld_in_path", "tld_in_subdomain", "abnormal_subdomain",
    "nb_subdomains", "prefix_suffix", "random_domain",
    "shortening_service", "path_extension", "nb_redirection",
    "nb_external_redirection", "length_words_raw", "char_repeat",
    "shortest_words_raw", "shortest_word_host", "shortest_word_path",
    "longest_words_raw", "longest_word_host", "longest_word_path",
    "avg_words_raw", "avg_word_host", "avg_word_path", "phish_hints",
    "domain_in_brand", "brand_in_subdomain", "brand_in_path",
    "suspecious_tld", "statistical_report", "nb_hyperlinks",
    "ratio_intHyperlinks", "ratio_extHyperlinks", "ratio_nullHyperlinks",
    "nb_extCSS", "ratio_intRedirection", "ratio_extRedirection",
    "ratio_intErrors", "ratio_extErrors", "login_form",
    "external_favicon", "links_in_tags", "submit_email",
    "ratio_intMedia", "ratio_extMedia", "sfh", "iframe",
    "popup_window", "safe_anchor", "onmouseover", "right_clic",
    "empty_title", "domain_in_title", "domain_with_copyright",
    "whois_registered_domain", "domain_registration_length",
    "domain_age", "web_traffic", "dns_record", "google_index",
    "page_rank",
]

SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "twit.ac",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online",
    "site", "website", "space", "fun", "icu", "buzz", "click", "pw", "cc",
}

PHISH_HINTS = [
    "secure", "account", "update", "login", "signin", "verify",
    "banking", "confirm", "password", "credential", "paypal",
    "ebay", "amazon", "apple", "microsoft", "google",
]

BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "instagram", "whatsapp", "ebay", "twitter", "bank",
    "wellsfargo", "citibank", "chase", "hsbc", "barclays",
]

PATH_EXTENSIONS = {
    ".exe", ".zip", ".rar", ".tar", ".gz", ".7z", ".msi",
    ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
}


def _words(text):
    return re.split(r"[\W_]+", text) if text else []


def _char_repeat(url):
    if len(url) < 2:
        return 0
    return sum(1 for i in range(1, len(url)) if url[i] == url[i - 1])


def _is_random_domain(hostname):
    name = hostname.split(".")[0] if "." in hostname else hostname
    if len(name) < 5:
        return 0
    vowels = sum(1 for c in name.lower() if c in "aeiou")
    return 1 if (vowels / len(name)) < 0.2 else 0


def extract_features(url: str) -> list:
    try:
        parsed   = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path     = (parsed.path or "").lower()
        full     = url.lower()

        tld   = hostname.split(".")[-1] if "." in hostname else ""
        parts = [p for p in hostname.split(".") if p]
        n_sub = max(0, len(parts) - 2)

        digits_url  = sum(c.isdigit() for c in url)
        digits_host = sum(c.isdigit() for c in hostname)

        words_raw  = _words(url)
        words_host = _words(hostname)
        words_path = _words(path)

        len_words_raw  = len(words_raw)
        len_words_host = len(words_host)
        len_words_path = len(words_path)

        shortest_raw  = min((len(w) for w in words_raw  if w), default=0)
        shortest_host = min((len(w) for w in words_host if w), default=0)
        shortest_path = min((len(w) for w in words_path if w), default=0)
        longest_raw   = max((len(w) for w in words_raw  if w), default=0)
        longest_host  = max((len(w) for w in words_host if w), default=0)
        longest_path  = max((len(w) for w in words_path if w), default=0)
        avg_raw  = sum(len(w) for w in words_raw  if w) / max(len_words_raw,  1)
        avg_host = sum(len(w) for w in words_host if w) / max(len_words_host, 1)
        avg_path = sum(len(w) for w in words_path if w) / max(len_words_path, 1)

        has_port   = 1 if parsed.port and parsed.port not in (80, 443) else 0
        is_ip      = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
        is_puny    = 1 if "xn--" in hostname else 0
        has_prefix = 1 if parts and "-" in parts[0] else 0

        path_ext  = 1 if any(path.endswith(e) for e in PATH_EXTENSIONS) else 0
        is_short  = 1 if any(s in hostname for s in SHORTENING_SERVICES) else 0
        susp_tld  = 1 if tld in SUSPICIOUS_TLDS else 0

        phish_hint = sum(1 for h in PHISH_HINTS if h in full)
        brand_sub  = 1 if any(b in hostname and b not in ".".join(parts[-2:]) for b in BRANDS) else 0
        brand_path = 1 if any(b in path for b in BRANDS) else 0
        dom_brand  = 1 if any(b in ".".join(parts[-2:]) for b in BRANDS) else 0

        tld_in_path = 1 if tld and tld in path else 0
        tld_in_sub  = 1 if tld and any(tld in p for p in parts[:-2]) else 0
        abnormal_sub = 1 if n_sub >= 3 else 0

        http_in_path = 1 if "http" in path else 0
        https_token  = 1 if "https" in hostname else 0
        nb_dslash    = max(0, url.count("//") - 1)

        return [
            len(url),
            len(hostname),
            is_ip,
            url.count("."),
            url.count("-"),
            url.count("@"),
            url.count("?"),
            url.count("&"),
            url.count("|"),
            url.count("="),
            url.count("_"),
            url.count("~"),
            url.count("%"),
            url.count("/"),
            url.count("*"),
            url.count(":"),
            url.count(","),
            url.count(";"),
            url.count("$"),
            url.count(" "),
            1 if "www." in hostname else 0,
            url.count(".com"),
            nb_dslash,
            http_in_path,
            https_token,
            round(digits_url  / max(len(url),      1), 4),
            round(digits_host / max(len(hostname),  1), 4),
            is_puny,
            has_port,
            tld_in_path,
            tld_in_sub,
            abnormal_sub,
            n_sub,
            has_prefix,
            _is_random_domain(hostname),
            is_short,
            path_ext,
            nb_dslash,
            0,
            len_words_raw,
            _char_repeat(url),
            shortest_raw,
            shortest_host,
            shortest_path,
            longest_raw,
            longest_host,
            longest_path,
            round(avg_raw,  2),
            round(avg_host, 2),
            round(avg_path, 2),
            phish_hint,
            dom_brand,
            brand_sub,
            brand_path,
            susp_tld,
            0,
            0,
            0.0,
            0.0,
            0.0,
            0,
            0.0,
            0.0,
            0.0,
            0.0,
            0,
            0,
            0.0,
            0,
            0.0,
            0.0,
            0,
            0,
            0,
            0.0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            -1,
            0,
            0,
            0,
            0,
        ]
    except Exception:
        return [0] * len(FEATURE_COLS)
