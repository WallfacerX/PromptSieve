from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PROMPTSIEVE_", env_file=".env", extra="ignore", hide_input_in_errors=True
    )
    proxy_token: SecretStr
    openai_api_key: SecretStr
    mode: str = "enforce"
    upstream_origin: str = "https://api.openai.com"
    max_request_bytes: int = Field(default=1048576, gt=0)
    max_concurrency: int = Field(default=32, gt=0)
    body_timeout: float = Field(default=15, gt=0)
    connect_timeout: float = Field(default=10, gt=0)
    read_timeout: float = Field(default=60, gt=0)
    total_timeout: float = Field(default=300, gt=0)

    @model_validator(mode="after")
    def validate_security(self):
        token, key = self.proxy_token.get_secret_value(), self.openai_api_key.get_secret_value()
        if not token or not key or token == key:
            raise ValueError("Distinct nonempty proxy and upstream credentials are required")
        if self.mode not in {"enforce", "monitor"}:
            raise ValueError("Mode must be enforce or monitor")
        origin = urlsplit(self.upstream_origin)
        if origin.port is not None and not 1 <= origin.port <= 65535:
            raise ValueError("Invalid upstream port")
        if (
            origin.scheme != "https"
            or not origin.hostname
            or origin.username
            or origin.password
            or origin.query
            or origin.fragment
            or origin.path
        ):
            raise ValueError("Upstream must be an HTTPS origin without path or credentials")
        return self
