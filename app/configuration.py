"""Environment-specific resource metadata, kept outside published source."""
import json
import os
from .store import ROOT


class ConfigurationError(ValueError):
    pass


def deployment_json(variable, relative_path):
    raw = os.getenv(variable)
    if raw is None:
        raw = (ROOT/'config'/relative_path).read_text(encoding='utf-8-sig')
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        raise ConfigurationError(f'{variable} 연결 설정의 JSON 형식을 확인해 주세요.') from None
    if not isinstance(value, dict):
        raise ConfigurationError(f'{variable} 연결 설정은 JSON 객체여야 합니다.')
    return value
