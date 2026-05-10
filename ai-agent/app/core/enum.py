PAGINATION_KEYWORDS = {
        "page", "limit", "offset", "sort", "size",
        "per_page", "page_size", "cursor", "skip", "take"
    }

    # ── API5 / API6 / API9: keyword nhạy cảm trong path ──────────────
SENSITIVE_PATH_KEYWORDS = {
        # API5 — BFLA: action của admin/role cao
        "admin":        "API5_BFLA",
        "internal":     "API5_BFLA",
        "manage":       "API5_BFLA",
        "management":   "API5_BFLA",
        "superuser":    "API5_BFLA",
        "moderator":    "API5_BFLA",
        "impersonate":  "API5_BFLA",

        # API6 — Sensitive Business Flows
        "checkout":     "API6_BusinessFlow",
        "payment":      "API6_BusinessFlow",
        "transfer":     "API6_BusinessFlow",
        "withdraw":     "API6_BusinessFlow",
        "refund":       "API6_BusinessFlow",
        "purchase":     "API6_BusinessFlow",
        "subscribe":    "API6_BusinessFlow",
        "promo":        "API6_BusinessFlow",
        "coupon":       "API6_BusinessFlow",
        "redeem":       "API6_BusinessFlow",
        "vote":         "API6_BusinessFlow",
        "review":       "API6_BusinessFlow",

        # API8 — Security Misconfiguration
        "config":       "API8_Misconfig",
        "settings":     "API8_Misconfig",
        "env":          "API8_Misconfig",
        "debug":        "API8_Misconfig",
        "test":         "API8_Misconfig",
        "swagger":      "API8_Misconfig",
        "openapi":      "API8_Misconfig",
        "actuator":     "API8_Misconfig",
        "metrics":      "API8_Misconfig",
        "health":       "API8_Misconfig",

        # API9 — Improper Inventory Management
        "v1":           "API9_Inventory",
        "v2":           "API9_Inventory",
        "v3":           "API9_Inventory",
        "deprecated":   "API9_Inventory",
        "legacy":       "API9_Inventory",
        "old":          "API9_Inventory",
        "beta":         "API9_Inventory",
        "internal-api": "API9_Inventory",
        "undocumented": "API9_Inventory",

        # API2 — Broken Auth
        "password-reset":   "API2_BrokenAuth",
        "forgot-password":  "API2_BrokenAuth",
        "reset-password":   "API2_BrokenAuth",
        "change-password":  "API2_BrokenAuth",
        "verify":           "API2_BrokenAuth",
        "otp":              "API2_BrokenAuth",
        "2fa":              "API2_BrokenAuth",
        "token":            "API2_BrokenAuth",
        "refresh":          "API2_BrokenAuth",
    }

    # ── API7 — SSRF: tham số chứa URL ─────────────────────────────────
SSRF_PARAM_KEYWORDS = {
        "url", "uri", "webhook", "callback",
        "source", "dest", "target", "redirect",
        "proxy", "fetch", "forward", "remote",
        "endpoint", "host", "link", "href",
    }

    # ── API3 — field nhạy cảm trong requestBody schema ───────────────
    # Nếu schema có những field này mà không filter → nguy cơ mass assignment
SENSITIVE_BODY_FIELDS = {
        "role", "is_admin", "admin", "permission",
        "privilege", "group", "verified", "active",
        "status", "balance", "credit", "score",
        "internal", "approved", "superuser",
    }

    # ── API10 — third-party / external integration ────────────────────
THIRD_PARTY_KEYWORDS = {
        "webhook", "integration", "provider",
        "external", "third-party", "oauth",
        "connect", "sync", "import", "export",
        "feed", "rss", "scrape",
    }
