# Dev-only CloudTrail log dataset. Not deployed to Lambda.
# Follows the real CloudTrail JSON schema.
# Geographic location is not present in CloudTrail — it requires GeoIP enrichment on sourceIPAddress.
# failed_attempts is not present in a single event — it requires cross-event aggregation.

LOGS = [
    # --- alice: ConsoleLogin failure, off-hours (02:13 UTC), no MFA, malicious IP ---
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE00001",
            "arn": "arn:aws:iam::111122223333:user/alice",
            "accountId": "111122223333",
            "userName": "alice",
        },
        "eventTime": "2024-01-15T02:13:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "additionalEventData": {
            "MFAUsed": "No",
            "LoginTo": "https://console.aws.amazon.com/",
            "MobileVersion": "No",
        },
        "responseElements": {"ConsoleLogin": "Failure"},
        "errorMessage": "Failed authentication",
        "requestID": "aaaaaaaa-0001-0001-0001-aaaaaaaaaaaa",
        "eventID": "bbbbbbbb-0001-0001-0001-bbbbbbbbbbbb",
        "eventType": "AwsConsoleSignIn",
        "managementEvent": True,
        "eventCategory": "Management",
    },

    # --- bob: clean ConsoleLogin, business hours, MFA used ---
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE00002",
            "arn": "arn:aws:iam::111122223333:user/bob",
            "accountId": "111122223333",
            "userName": "bob",
        },
        "eventTime": "2024-01-15T09:45:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "10.1.2.3",
        "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "additionalEventData": {
            "MFAUsed": "Yes",
            "LoginTo": "https://console.aws.amazon.com/",
            "MobileVersion": "No",
        },
        "responseElements": {"ConsoleLogin": "Success"},
        "requestID": "aaaaaaaa-0002-0002-0002-aaaaaaaaaaaa",
        "eventID": "bbbbbbbb-0002-0002-0002-bbbbbbbbbbbb",
        "eventType": "AwsConsoleSignIn",
        "managementEvent": True,
        "eventCategory": "Management",
    },

    # --- carol: AssumeRole, business hours, MFA-backed session ---
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE00003",
            "arn": "arn:aws:iam::111122223333:user/carol",
            "accountId": "111122223333",
            "userName": "carol",
            "sessionContext": {
                "attributes": {
                    "mfaAuthenticated": "true",
                    "creationDate": "2024-01-15T14:00:00Z",
                },
            },
        },
        "eventTime": "2024-01-15T14:22:00Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "10.0.1.50",
        "userAgent": "aws-cli/2.13.0 Python/3.11.0",
        "requestParameters": {
            "roleArn": "arn:aws:iam::111122223333:role/developer",
            "roleSessionName": "carol-session",
        },
        "responseElements": {
            "credentials": {
                "accessKeyId": "ASIAEXAMPLE00003",
                "expiration": "Jan 15, 2024, 10:22:00 PM",
            },
        },
        "requestID": "aaaaaaaa-0003-0003-0003-aaaaaaaaaaaa",
        "eventID": "bbbbbbbb-0003-0003-0003-bbbbbbbbbbbb",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "eventCategory": "Management",
    },

    # --- dave: GetSecretValue, MFA status unknown (no sessionContext attributes) ---
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE00004",
            "arn": "arn:aws:iam::111122223333:user/dave",
            "accountId": "111122223333",
            "userName": "dave",
        },
        "eventTime": "2024-01-15T11:05:00Z",
        "eventSource": "secretsmanager.amazonaws.com",
        "eventName": "GetSecretValue",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.77",
        "userAgent": "aws-sdk-python/1.29.0",
        "requestParameters": {"secretId": "prod/db/password"},
        "responseElements": None,
        "requestID": "aaaaaaaa-0004-0004-0004-aaaaaaaaaaaa",
        "eventID": "bbbbbbbb-0004-0004-0004-bbbbbbbbbbbb",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "eventCategory": "Management",
    },

    # --- eve: GetSecretValue, off-hours (23:47 UTC), malicious IP, no MFA ---
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROAEXAMPLE00005:eve-session",
            "arn": "arn:aws:sts::111122223333:assumed-role/ops-role/eve-session",
            "accountId": "111122223333",
            "accessKeyId": "ASIAEXAMPLE00005",
            "sessionContext": {
                "attributes": {
                    "mfaAuthenticated": "false",
                    "creationDate": "2024-01-15T23:40:00Z",
                },
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAEXAMPLE00005",
                    "arn": "arn:aws:iam::111122223333:role/ops-role",
                    "accountId": "111122223333",
                    "userName": "eve",
                },
            },
        },
        "eventTime": "2024-01-15T23:47:00Z",
        "eventSource": "secretsmanager.amazonaws.com",
        "eventName": "GetSecretValue",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "10.0.0.99",
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {"secretId": "prod/api/key"},
        "responseElements": None,
        "requestID": "aaaaaaaa-0005-0005-0005-aaaaaaaaaaaa",
        "eventID": "bbbbbbbb-0005-0005-0005-bbbbbbbbbbbb",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "eventCategory": "Management",
    },

    # --- frank: CreateUser, off-hours (03:30 UTC), no MFA ---
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE00006",
            "arn": "arn:aws:iam::111122223333:user/frank",
            "accountId": "111122223333",
            "userName": "frank",
            "sessionContext": {
                "attributes": {
                    "mfaAuthenticated": "false",
                    "creationDate": "2024-01-15T03:25:00Z",
                },
            },
        },
        "eventTime": "2024-01-15T03:30:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "172.16.0.5",
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {"userName": "svc-backdoor"},
        "responseElements": {
            "user": {
                "userName": "svc-backdoor",
                "arn": "arn:aws:iam::111122223333:user/svc-backdoor",
                "createDate": "Jan 15, 2024, 3:30:00 AM",
            },
        },
        "requestID": "aaaaaaaa-0006-0006-0006-aaaaaaaaaaaa",
        "eventID": "bbbbbbbb-0006-0006-0006-bbbbbbbbbbbb",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "eventCategory": "Management",
    },

    # --- frank: AttachUserPolicy 1 minute later — privilege escalation pattern ---
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE00006",
            "arn": "arn:aws:iam::111122223333:user/frank",
            "accountId": "111122223333",
            "userName": "frank",
            "sessionContext": {
                "attributes": {
                    "mfaAuthenticated": "false",
                    "creationDate": "2024-01-15T03:25:00Z",
                },
            },
        },
        "eventTime": "2024-01-15T03:31:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "172.16.0.5",
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {
            "userName": "svc-backdoor",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
        "responseElements": None,
        "requestID": "aaaaaaaa-0007-0007-0007-aaaaaaaaaaaa",
        "eventID": "bbbbbbbb-0007-0007-0007-bbbbbbbbbbbb",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "eventCategory": "Management",
    },

    # --- grace: DeleteTrail (defense evasion), malicious IP, MFA unknown ---
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROAEXAMPLE00008:grace-session",
            "arn": "arn:aws:sts::111122223333:assumed-role/admin-role/grace-session",
            "accountId": "111122223333",
            "accessKeyId": "ASIAEXAMPLE00008",
            "sessionContext": {
                "attributes": {
                    "mfaAuthenticated": "false",
                    "creationDate": "2024-01-15T04:00:00Z",
                },
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAEXAMPLE00008",
                    "arn": "arn:aws:iam::111122223333:role/admin-role",
                    "accountId": "111122223333",
                    "userName": "grace",
                },
            },
        },
        "eventTime": "2024-01-15T04:00:00Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "DeleteTrail",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "192.168.100.1",
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {
            "name": "arn:aws:cloudtrail:us-east-1:111122223333:trail/management-events",
        },
        "responseElements": None,
        "requestID": "aaaaaaaa-0008-0008-0008-aaaaaaaaaaaa",
        "eventID": "bbbbbbbb-0008-0008-0008-bbbbbbbbbbbb",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "eventCategory": "Management",
    },

    # --- henry: AssumeRole with a malformed eventTime (tests normalize_time fallback) ---
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE00009",
            "arn": "arn:aws:iam::111122223333:user/henry",
            "accountId": "111122223333",
            "userName": "henry",
            "sessionContext": {
                "attributes": {
                    "mfaAuthenticated": "true",
                    "creationDate": "2024-01-15T10:00:00Z",
                },
            },
        },
        "eventTime": "not-a-timestamp",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "10.2.3.4",
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {
            "roleArn": "arn:aws:iam::111122223333:role/readonly",
            "roleSessionName": "henry-session",
        },
        "responseElements": {
            "credentials": {
                "accessKeyId": "ASIAEXAMPLE00009",
                "expiration": "Jan 15, 2024, 6:00:00 PM",
            },
        },
        "requestID": "aaaaaaaa-0009-0009-0009-aaaaaaaaaaaa",
        "eventID": "bbbbbbbb-0009-0009-0009-bbbbbbbbbbbb",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "eventCategory": "Management",
    },

    # --- iris: ConsoleLogin, minimal userIdentity (tests fallback user extraction) ---
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE00010",
            "arn": "arn:aws:iam::111122223333:user/iris",
            "accountId": "111122223333",
            "userName": "iris",
        },
        "eventTime": "2024-01-15T10:00:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "10.10.10.10",
        "userAgent": "Mozilla/5.0",
        "additionalEventData": {
            "LoginTo": "https://console.aws.amazon.com/",
            "MobileVersion": "No",
        },
        "responseElements": {"ConsoleLogin": "Success"},
        "requestID": "aaaaaaaa-0010-0010-0010-aaaaaaaaaaaa",
        "eventID": "bbbbbbbb-0010-0010-0010-bbbbbbbbbbbb",
        "eventType": "AwsConsoleSignIn",
        "managementEvent": True,
        "eventCategory": "Management",
    },
]
