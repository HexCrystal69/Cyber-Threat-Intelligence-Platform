import re
import ipaddress
from urllib.parse import urlparse

# Regex patterns
DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
)
EMAIL_REGEX = re.compile(
    r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
)
HASH_MD5_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')
HASH_SHA1_REGEX = re.compile(r'^[a-fA-F0-9]{40}$')
HASH_SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')

def validate_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def validate_domain(value: str) -> bool:
    return bool(DOMAIN_REGEX.match(value))

def validate_email(value: str) -> bool:
    return bool(EMAIL_REGEX.match(value))

def validate_hash_md5(value: str) -> bool:
    return bool(HASH_MD5_REGEX.match(value))

def validate_hash_sha1(value: str) -> bool:
    return bool(HASH_SHA1_REGEX.match(value))

def validate_hash_sha256(value: str) -> bool:
    return bool(HASH_SHA256_REGEX.match(value))

def validate_url(value: str) -> bool:
    try:
        result = urlparse(value)
        # Check scheme and netloc (or path if it's relative, but threat URLs must have netloc)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def validate_ioc(value: str, ioc_type: str) -> bool:
    ioc_type_upper = ioc_type.upper()
    if ioc_type_upper == "IP":
        return validate_ip(value)
    elif ioc_type_upper == "DOMAIN":
        return validate_domain(value)
    elif ioc_type_upper == "EMAIL":
        return validate_email(value)
    elif ioc_type_upper == "HASH_MD5":
        return validate_hash_md5(value)
    elif ioc_type_upper == "HASH_SHA1":
        return validate_hash_sha1(value)
    elif ioc_type_upper == "HASH_SHA256":
        return validate_hash_sha256(value)
    elif ioc_type_upper == "URL":
        return validate_url(value)
    return False
