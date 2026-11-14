"""
Feature extraction from a live URL.
Extracts all 87 features matching dataset_phishing.csv columns.
Must stay in sync with backend/feature_extractor.py
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
    """Heuristic: high consonant ratio suggests random/generated domain."""
    name = hostname.split(".")[0] if "." in hostname else hostname
    if len(name) < 5:
        return 0
    vowels = sum(1 for c in name.lower() if c in "aeiou")
    ratio = vowels / len(name)
    return 1 if ratio < 0.2 else 0


def extract_features(url: str) -> list:
    try:
        parsed   = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path     = (parsed.path or "").lower()
        full     = url.lower()

        tld = hostname.split(".")[-1] if "." in hostname else ""
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

        path_ext = 1 if any(path.endswith(e) for e in PATH_EXTENSIONS) else 0
        is_short  = 1 if any(s in hostname for s in SHORTENING_SERVICES) else 0
        susp_tld  = 1 if tld in SUSPICIOUS_TLDS else 0

        phish_hint = sum(1 for h in PHISH_HINTS if h in full)
        brand_sub  = 1 if any(b in hostname and b not in ".".join(parts[-2:]) for b in BRANDS) else 0
        brand_path = 1 if any(b in path for b in BRANDS) else 0
        dom_brand  = 1 if any(b in ".".join(parts[-2:]) for b in BRANDS) else 0

        tld_in_path = 1 if tld and tld in path else 0
        tld_in_sub  = 1 if tld and any(tld in p for p in parts[:-2]) else 0
        abnormal_sub = 1 if n_sub >= 3 else 0

        http_in_path  = 1 if "http" in path else 0
        https_token   = 1 if "https" in hostname else 0
        nb_dslash     = url.count("//") - 1  # subtract the scheme's //
        nb_redirection = max(0, nb_dslash)

        return [
            len(url),                          # length_url
            len(hostname),                     # length_hostname
            is_ip,                             # ip
            url.count("."),                    # nb_dots
            url.count("-"),                    # nb_hyphens
            url.count("@"),                    # nb_at
            url.count("?"),                    # nb_qm
            url.count("&"),                    # nb_and
            url.count("|"),                    # nb_or
            url.count("="),                    # nb_eq
            url.count("_"),                    # nb_underscore
            url.count("~"),                    # nb_tilde
            url.count("%"),                    # nb_percent
            url.count("/"),                    # nb_slash
            url.count("*"),                    # nb_star
            url.count(":"),                    # nb_colon
            url.count(","),                    # nb_comma
            url.count(";"),                    # nb_semicolumn
            url.count("$"),                    # nb_dollar
            url.count(" "),                    # nb_space
            1 if "www." in hostname else 0,    # nb_www
            url.count(".com"),                 # nb_com
            max(0, nb_dslash),                 # nb_dslash
            http_in_path,                      # http_in_path
            https_token,                       # https_token
            round(digits_url / max(len(url), 1), 4),      # ratio_digits_url
            round(digits_host / max(len(hostname), 1), 4),# ratio_digits_host
            is_puny,                           # punycode
            has_port,                          # port
            tld_in_path,                       # tld_in_path
            tld_in_sub,                        # tld_in_subdomain
            abnormal_sub,                      # abnormal_subdomain
            n_sub,                             # nb_subdomains
            has_prefix,                        # prefix_suffix
            _is_random_domain(hostname),       # random_domain
            is_short,                          # shortening_service
            path_ext,                          # path_extension
            nb_redirection,                    # nb_redirection
            0,                                 # nb_external_redirection (needs page content)
            len_words_raw,                     # length_words_raw
            _char_repeat(url),                 # char_repeat
            shortest_raw,                      # shortest_words_raw
            shortest_host,                     # shortest_word_host
            shortest_path,                     # shortest_word_path
            longest_raw,                       # longest_words_raw
            longest_host,                      # longest_word_host
            longest_path,                      # longest_word_path
            round(avg_raw,  2),                # avg_words_raw
            round(avg_host, 2),                # avg_word_host
            round(avg_path, 2),                # avg_word_path
            phish_hint,                        # phish_hints
            dom_brand,                         # domain_in_brand
            brand_sub,                         # brand_in_subdomain
            brand_path,                        # brand_in_path
            susp_tld,                          # suspecious_tld
            0,                                 # statistical_report (external lookup)
            0,                                 # nb_hyperlinks (needs page content)
            0.0,                               # ratio_intHyperlinks
            0.0,                               # ratio_extHyperlinks
            0.0,                               # ratio_nullHyperlinks
            0,                                 # nb_extCSS
            0.0,                               # ratio_intRedirection
            0.0,                               # ratio_extRedirection
            0.0,                               # ratio_intErrors
            0.0,                               # ratio_extErrors
            0,                                 # login_form
            0,                                 # external_favicon
            0.0,                               # links_in_tags
            0,                                 # submit_email
            0.0,                               # ratio_intMedia
            0.0,                               # ratio_extMedia
            0,                                 # sfh
            0,                                 # iframe
            0,                                 # popup_window
            0.0,                               # safe_anchor
            0,                                 # onmouseover
            0,                                 # right_clic
            0,                                 # empty_title
            0,                                 # domain_in_title
            0,                                 # domain_with_copyright
            0,                                 # whois_registered_domain
            0,                                 # domain_registration_length
            -1,                                # domain_age (unknown)
            0,                                 # web_traffic
            0,                                 # dns_record
            0,                                 # google_index
            0,                                 # page_rank
        ]
    except Exception:
        return [0] * len(FEATURE_COLS)
