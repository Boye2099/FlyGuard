from pydantic import BaseModel
from typing import List


class ScanRequest(BaseModel):
    domain: str
    url: str
    protocol: str
    is_https: bool

    links: int
    scripts: int
    images: int
    forms: int
    iframes: int
    resources: int

    third_party_domains: List[str]

    password_fields: int
    insecure_forms: int
    mixed_content: bool

    inline_scripts: int
    external_scripts: int

    has_csp: bool

    cookie_count: int

    headers: dict[str, str]