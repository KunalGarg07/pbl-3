"""Scan a small Python project uploaded as a .zip archive (week 10).

Safety:
- The archive is rejected if any entry has an absolute path, a drive letter or a `..` component
  (zip-slip), or is a symbolic link.
- Limits on the number of Python files, the size of each file and the total extracted size protect
  against zip bombs. Sizes are checked while reading, not trusted from the archive header.
- Only .py files are extracted, into a temporary directory that is deleted afterwards. Nothing is executed.
"""
import hashlib
import stat
import tempfile
import time
import uuid
import zipfile
from io import BytesIO
from pathlib import Path, PurePosixPath

from codeguard.pipeline import InputError, bandit_to_findings, ml_to_findings
from codeguard.scanner import ml_detector, risk_assessor
from codeguard.scanner.static_analyzer import AnalyzerError, run_bandit_dir
from codeguard.schemas import EngineStatus, ScanResult

MAX_ARCHIVE_BYTES = 10_000_000
MAX_PY_FILES = 500
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 20_000_000


def _safe_member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or (path.parts and path.parts[0].endswith(":")) or ".." in path.parts:
        raise InputError(f"Unsafe path in archive: '{name}'. The archive was rejected.")
    return path


def safe_extract(archive_bytes: bytes, destination: Path) -> tuple[list[str], int]:
    """Extract only .py files. Returns (relative paths, number of other files skipped)."""
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise InputError(f"Archive is too large ({len(archive_bytes):,} bytes; limit {MAX_ARCHIVE_BYTES:,}).")
    try:
        archive = zipfile.ZipFile(BytesIO(archive_bytes))
    except zipfile.BadZipFile as exc:
        raise InputError("The file is not a valid .zip archive.") from exc

    members = archive.infolist()
    for info in members:  # validate every entry before writing anything
        _safe_member_path(info.filename)
        if stat.S_ISLNK(info.external_attr >> 16):
            raise InputError(f"Symbolic link in archive: '{info.filename}'. The archive was rejected.")

    extracted, skipped, total = [], 0, 0
    for info in members:
        if info.is_dir():
            continue
        rel = _safe_member_path(info.filename)
        if rel.suffix != ".py" or any(part.startswith(".") or part == "__pycache__" for part in rel.parts):
            skipped += 1
            continue
        if len(extracted) >= MAX_PY_FILES:
            raise InputError(f"Too many Python files (limit {MAX_PY_FILES}).")
        with archive.open(info) as src:
            data = src.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            skipped += 1
            continue
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise InputError(f"Extracted size exceeds {MAX_TOTAL_BYTES:,} bytes.")
        target = destination.joinpath(*rel.parts)
        if destination.resolve() not in target.resolve().parents:
            raise InputError(f"Unsafe path in archive: '{info.filename}'. The archive was rejected.")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        extracted.append(rel.as_posix())
    if not extracted:
        raise InputError("The archive contains no Python (.py) files.")
    return sorted(extracted), skipped


def scan_repository(archive_bytes: bytes, archive_name: str = "project.zip", *, use_ml: bool = True,
                    store=None) -> ScanResult:
    started = time.perf_counter()
    engines: dict[str, EngineStatus] = {}
    with tempfile.TemporaryDirectory(prefix="codeguard_repo_") as tmp:
        root = Path(tmp)
        files, skipped = safe_extract(archive_bytes, root)

        texts, unparsable = {}, []
        for rel in files:
            try:
                texts[rel] = root.joinpath(*rel.split("/")).read_bytes().decode("utf-8-sig")
            except UnicodeDecodeError:
                unparsable.append(rel)

        issues_by_file: dict[str, list] = {rel: [] for rel in texts}
        try:
            report = run_bandit_dir(root)
            for issue in report.issues:
                rel = Path(issue["filename"]).resolve().relative_to(root.resolve()).as_posix()
                issues_by_file.setdefault(rel, []).append(issue)
            detail = f"Bandit {report.version}, {len(texts)} file(s)"
            if report.errors:
                detail += f"; {len(report.errors)} file(s) could not be parsed"
            engines["bandit"] = EngineStatus(status="ok", detail=detail)
        except AnalyzerError as exc:
            engines["bandit"] = EngineStatus(status="error", detail=str(exc))

    findings, model_version, units = [], None, 0
    counter = 1
    bandit_by_file = {}
    for rel, text in texts.items():
        bandit_by_file[rel] = bandit_to_findings(issues_by_file.get(rel, []), text, rel, start=counter)
        counter += len(bandit_by_file[rel])
        findings += bandit_by_file[rel]

    if use_ml:
        try:
            _, card = ml_detector.load_model()
            model_version = card.get("model_version")
            for rel, text in texts.items():
                try:
                    ml_findings, n = ml_to_findings(text, rel, bandit_by_file[rel], start=counter)
                except SyntaxError:
                    continue
                counter += len(ml_findings)
                units += n
                findings += ml_findings
            engines["ml"] = EngineStatus(status="ok", detail=f"{units} code unit(s) scored")
        except ml_detector.ModelUnavailable as exc:
            engines["ml"] = EngineStatus(status="unavailable", detail=str(exc))
    else:
        engines["ml"] = EngineStatus(status="unavailable", detail="Disabled for this scan")

    for i, f in enumerate(findings, start=1):  # stable, unique ids across the whole project
        f.finding_id = f"{'B' if f.source == 'bandit' else 'M'}{i:04d}"
    findings = sorted(findings, key=lambda f: (f.severity.rank, f.file, f.line))
    result = ScanResult(
        scan_id=uuid.uuid4().hex[:12], filename=archive_name[:100], kind="repository",
        files=sorted(texts), skipped_files=skipped + len(unparsable),
        source_sha256=hashlib.sha256(archive_bytes).hexdigest(),
        lines_of_code=sum(len(t.splitlines()) for t in texts.values()),
        duration_ms=int((time.perf_counter() - started) * 1000),
        engines=engines, findings=findings, summary=risk_assessor.summarize(findings),
        model_version=model_version,
    )
    if store is not None:
        store.save(result)
    return result
