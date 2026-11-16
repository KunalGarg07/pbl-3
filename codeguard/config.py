"""Settings, read from environment variables (see .env.example)."""
import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader so we do not need an extra dependency. Existing variables win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


_load_dotenv(PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    max_bytes: int = int(os.getenv("CODEGUARD_MAX_BYTES", "200000"))
    allowed_extensions: tuple = (".py",)
    store_source: bool = _bool(os.getenv("CODEGUARD_STORE_SOURCE", "false"))
    db_path: Path = PROJECT_ROOT / os.getenv("CODEGUARD_DB_PATH", "codeguard_data/scans.db")
    bandit_timeout_s: int = int(os.getenv("CODEGUARD_BANDIT_TIMEOUT", "30"))
    model_path: Path = PROJECT_ROOT / "artifacts" / "model" / "python_vuln_model.joblib"
    model_card_path: Path = PROJECT_ROOT / "artifacts" / "model" / "model_card.json"
    metrics_dir: Path = PROJECT_ROOT / "artifacts" / "metrics"
    figures_dir: Path = PROJECT_ROOT / "artifacts" / "figures"
    # Units shorter than this many non-blank lines are not scored by the ML model.
    ml_min_lines: int = 2
    supported_languages: tuple = field(default=("python",))
    # Knowledge base (week 7)
    kb_dir: Path = PROJECT_ROOT / "knowledge_base"
    kb_index_dir: Path = PROJECT_ROOT / "knowledge_base" / "index"
    embedding_model: str = os.getenv("CODEGUARD_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    # LLM (week 8): "ollama", "anthropic" or "none" (retrieval-only explanations)
    llm_provider: str = os.getenv("CODEGUARD_LLM_PROVIDER", "ollama")
    ollama_url: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.2")
    anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
    llm_timeout_s: int = int(os.getenv("CODEGUARD_LLM_TIMEOUT", "180"))


settings = Settings()
