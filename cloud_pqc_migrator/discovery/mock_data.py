"""
Realistic mock CLI JSON responses for --dry-run mode.
Each key maps to the mock_key used in DiscoveryStep.
"""

MOCK_RESPONSES: dict[str, dict | list] = {
    # ── AWS ────────────────────────────────────────────────────────────────
    "aws_load_balancers": {
        "LoadBalancers": [
            {
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/0123456789abcdef",
                "DNSName": "prod-alb-1234567890.us-east-1.elb.amazonaws.com",
                "LoadBalancerName": "prod-alb",
                "Scheme": "internet-facing",
                "Type": "application",
                "State": {"Code": "active"},
            },
            {
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/internal-alb/abcdef0123456789",
                "DNSName": "internal-alb-0987654321.us-west-2.elb.amazonaws.com",
                "LoadBalancerName": "internal-alb",
                "Scheme": "internal",
                "Type": "application",
                "State": {"Code": "active"},
            },
        ]
    },
    "aws_listeners_prod_alb": {
        "Listeners": [
            {
                "ListenerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/prod-alb/0123456789abcdef/aaaa0000bbbb1111",
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/0123456789abcdef",
                "Port": 443,
                "Protocol": "HTTPS",
                "SslPolicy": "ELBSecurityPolicy-2016-08",
            }
        ]
    },
    "aws_listeners_internal_alb": {
        "Listeners": [
            {
                "ListenerArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/app/internal-alb/abcdef0123456789/cccc2222dddd3333",
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/internal-alb/abcdef0123456789",
                "Port": 443,
                "Protocol": "HTTPS",
                "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
            }
        ]
    },
    "aws_cloudfront_distributions": {
        "DistributionList": {
            "Items": [
                {
                    "Id": "E1ABCDEFGHIJKL",
                    "DomainName": "d1234567890abc.cloudfront.net",
                    "Aliases": {"Quantity": 1, "Items": ["api.example.com"]},
                    "ViewerCertificate": {
                        "MinimumProtocolVersion": "TLSv1.2_2021",
                        "SSLSupportMethod": "sni-only",
                    },
                    "Status": "Deployed",
                    "Origins": {
                        "Quantity": 1,
                        "Items": [{"DomainName": "origin.example.com", "Id": "myS3Origin"}],
                    },
                }
            ]
        }
    },
    "aws_acm_certificates": {
        "CertificateSummaryList": [
            {
                "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
                "DomainName": "api.example.com",
                "KeyAlgorithm": "RSA-2048",
                "Status": "ISSUED",
                "NotAfter": "2025-12-31T00:00:00Z",
            },
            {
                "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/aaaabbbb-cccc-dddd-eeee-ffffgggghhhh",
                "DomainName": "internal.example.com",
                "KeyAlgorithm": "EC-prime256v1",
                "Status": "ISSUED",
                "NotAfter": "2026-06-30T00:00:00Z",
            },
        ]
    },
    "aws_kms_keys": {
        "Keys": [
            {"KeyId": "aaaa1111-bbbb-2222-cccc-333344445555", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/aaaa1111-bbbb-2222-cccc-333344445555"},
            {"KeyId": "dddd6666-eeee-7777-ffff-888899990000", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/dddd6666-eeee-7777-ffff-888899990000"},
        ]
    },
    "aws_kms_key_aaaa1111": {
        "KeyMetadata": {
            "KeyId": "aaaa1111-bbbb-2222-cccc-333344445555",
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/aaaa1111-bbbb-2222-cccc-333344445555",
            "KeySpec": "RSA_2048",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Description": "Main data encryption key",
        }
    },
    "aws_kms_key_dddd6666": {
        "KeyMetadata": {
            "KeyId": "dddd6666-eeee-7777-ffff-888899990000",
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/dddd6666-eeee-7777-ffff-888899990000",
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Description": "S3 bucket encryption key",
        }
    },
    "aws_apigateway_domains": {
        "items": [
            {
                "domainName": "api.example.com",
                "securityPolicy": "TLS_1_0",
                "regionalDomainName": "d-abcdefg123.execute-api.us-east-1.amazonaws.com",
            }
        ]
    },
    # ── GCP ────────────────────────────────────────────────────────────────
    "gcp_ssl_policies": [
        {
            "name": "projects/my-project/global/sslPolicies/legacy-policy",
            "minTlsVersion": "TLS_1_2",
            "profile": "COMPATIBLE",
            "enabledFeatures": ["TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
            "fingerprint": "abcdefgh",
        },
        {
            "name": "projects/my-project/global/sslPolicies/modern-policy",
            "minTlsVersion": "TLS_1_3",
            "profile": "RESTRICTED",
            "enabledFeatures": ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"],
            "fingerprint": "ijklmnop",
        },
    ],
    "gcp_certificates": [
        {
            "name": "projects/my-project/locations/global/certificates/api-cert",
            "scope": "DEFAULT",
            "managed": {
                "domains": ["api.example.com"],
                "state": "ACTIVE",
            },
            "subjectAlternativeNames": ["api.example.com"],
        }
    ],
    "gcp_kms_keys": [
        {
            "name": "projects/my-project/locations/us-central1/keyRings/prod-keyring/cryptoKeys/data-key",
            "purpose": "ENCRYPT_DECRYPT",
            "primary": {
                "name": "projects/my-project/locations/us-central1/keyRings/prod-keyring/cryptoKeys/data-key/cryptoKeyVersions/1",
                "state": "ENABLED",
                "algorithm": "RSA_DECRYPT_OAEP_2048_SHA256",
            },
            "versionTemplate": {"algorithm": "RSA_DECRYPT_OAEP_2048_SHA256"},
        }
    ],
    "gcp_target_https_proxies": [
        {
            "name": "projects/my-project/global/targetHttpsProxies/prod-https-proxy",
            "sslPolicy": "projects/my-project/global/sslPolicies/legacy-policy",
            "urlMap": "projects/my-project/global/urlMaps/prod-url-map",
        }
    ],
}
