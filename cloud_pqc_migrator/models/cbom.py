from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"


class TLSVersion(str, Enum):
    TLS_1_0 = "TLS_1_0"
    TLS_1_1 = "TLS_1_1"
    TLS_1_2 = "TLS_1_2"
    TLS_1_3 = "TLS_1_3"
    UNKNOWN = "UNKNOWN"


class ResourceKind(str, Enum):
    ALB_LISTENER = "alb_listener"
    CLOUDFRONT_DISTRIBUTION = "cloudfront_distribution"
    ACM_CERTIFICATE = "acm_certificate"
    KMS_KEY = "kms_key"
    API_GATEWAY_DOMAIN = "api_gateway_domain"
    VPN_CONNECTION = "vpn_connection"
    GCP_SSL_POLICY = "gcp_ssl_policy"
    GCP_CERTIFICATE = "gcp_certificate"
    GCP_KMS_KEY = "gcp_kms_key"
    GCP_LB_TARGET_HTTPS_PROXY = "gcp_lb_target_https_proxy"


class CryptoAsset(BaseModel):
    resource_id: str
    resource_kind: ResourceKind
    provider: CloudProvider
    region: Optional[str] = None
    project: Optional[str] = None
    min_tls_version: TLSVersion = TLSVersion.UNKNOWN
    cipher_suites: list[str] = Field(default_factory=list)
    key_algorithm: Optional[str] = None
    key_length_bits: Optional[int] = None
    cert_expiry: Optional[datetime] = None
    is_internet_facing: bool = False
    raw_api_response: dict = Field(default_factory=dict)


class CBoM(BaseModel):
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    provider: CloudProvider
    account_id: Optional[str] = None
    dry_run: bool = False
    assets: list[CryptoAsset] = Field(default_factory=list)
    cli_commands_executed: list[str] = Field(default_factory=list)
