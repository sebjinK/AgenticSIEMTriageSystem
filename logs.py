# Dev-only log dataset. Not deployed to Lambda.
# Covers all five event types across clean and suspicious contexts.

LOGS = [
    # --- ConsoleLogin: failed brute-force, off-hours, no MFA, unusual location ---
    {
        "user":            "alice",
        "event":           "ConsoleLogin",
        "source_ip":       "203.0.113.5",   # malicious stub IP
        "time":            "02:13",
        "success":         False,
        "location":        "Russia",
        "mfa_used":        False,
        "failed_attempts": 7,
    },
    # --- ConsoleLogin: clean login ---
    {
        "user":            "bob",
        "event":           "ConsoleLogin",
        "source_ip":       "10.1.2.3",
        "time":            "09:45",
        "success":         True,
        "location":        "USA",
        "mfa_used":        True,
        "failed_attempts": 0,
    },
    # --- AssumeRole: successful, known location ---
    {
        "user":            "carol",
        "event":           "AssumeRole",
        "source_ip":       "10.0.1.50",
        "time":            "14:22",
        "success":         True,
        "location":        "USA",
        "mfa_used":        True,
        "failed_attempts": 0,
    },
    # --- GetSecretValue: borderline IP, MFA unknown ---
    {
        "user":            "dave",
        "event":           "GetSecretValue",
        "source_ip":       "198.51.100.77",
        "time":            "11:05",
        "success":         True,
        "location":        "USA",
        # mfa_used intentionally omitted → defaults to None
    },
    # --- GetSecretValue: off-hours, unusual location ---
    {
        "user":            "eve",
        "event":           "GetSecretValue",
        "source_ip":       "10.0.0.99",    # malicious stub IP
        "time":            "23:47",
        "success":         True,
        "location":        "China",
        "mfa_used":        False,
        "failed_attempts": 0,
    },
    # --- CreateUser: after-hours, unusual location ---
    {
        "user":            "frank",
        "event":           "CreateUser",
        "source_ip":       "172.16.0.5",
        "time":            "03:30",
        "success":         True,
        "location":        "Brazil",
        "mfa_used":        False,
        "failed_attempts": 0,
    },
    # --- AttachUserPolicy: follows CreateUser pattern, suspicious ---
    {
        "user":            "frank",
        "event":           "AttachUserPolicy",
        "source_ip":       "172.16.0.5",
        "time":            "03:31",
        "success":         True,
        "location":        "Brazil",
        "mfa_used":        False,
        "failed_attempts": 0,
    },
    # --- DeleteTrail: high-severity defense evasion ---
    {
        "user":            "grace",
        "event":           "DeleteTrail",
        "source_ip":       "192.168.100.1",  # malicious stub IP
        "time":            "04:00",
        "success":         True,
        "location":        "Unknown",
        "mfa_used":        None,
        "failed_attempts": 0,
    },
    # --- AssumeRole: missing time field (triggers normalize_time → None) ---
    {
        "user":            "henry",
        "event":           "AssumeRole",
        "source_ip":       "10.2.3.4",
        "time":            "not-a-time",
        "success":         True,
        "location":        "USA",
        "mfa_used":        True,
        "failed_attempts": 0,
    },
    # --- ConsoleLogin: clean, minimal fields (tests optional-field defaults) ---
    {
        "user":      "iris",
        "event":     "ConsoleLogin",
        "source_ip": "10.10.10.10",
        "time":      "10:00",
    },
]
