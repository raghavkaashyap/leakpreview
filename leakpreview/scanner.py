from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


SECRET_FILENAMES = {".env", "id_rsa", "id_dsa"}
SECRET_SUFFIXES = (".pem", ".key")
PRIVATE_FILENAMES = {".npmrc", ".pypirc", ".netrc"}
JUNK_FILENAMES = {".DS_Store", "Thumbs.db"}
JUNK_SUFFIXES = (".swp", ".swo", "~")
PRIVATE_PATH_PARTS = {".aws", ".ssh"}
JUNK_PATH_PARTS = {"__MACOSX"}
CATEGORY_ORDER = ("secrets", "private-files", "junk-metadata", "large-files")


@dataclass(frozen=True)
class Finding:
    category: str
    path: str
    reason: str
    size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "path": self.path,
            "reason": self.reason,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class ScanResult:
    target: str
    total_files: int
    findings: list[Finding]
    max_size_bytes: int

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    def grouped_findings(self) -> dict[str, list[Finding]]:
        grouped = {category: [] for category in CATEGORY_ORDER}
        for finding in self.findings:
            grouped[finding.category].append(finding)
        return grouped

    def to_dict(self) -> dict[str, object]:
        grouped = self.grouped_findings()
        return {
            "target": self.target,
            "total_files": self.total_files,
            "max_size_bytes": self.max_size_bytes,
            "has_findings": self.has_findings,
            "summary": {category: len(items) for category, items in grouped.items()},
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_text(self) -> str:
        grouped = self.grouped_findings()
        lines = [
            f"Target: {self.target}",
            f"Files scanned: {self.total_files}",
            f"Large file threshold: {format_bytes(self.max_size_bytes)}",
            "",
        ]
        for category in CATEGORY_ORDER:
            items = grouped[category]
            lines.append(f"{category} ({len(items)})")
            for item in items:
                size_suffix = f" [{format_bytes(item.size_bytes)}]" if item.size_bytes else ""
                lines.append(f"  - {item.path}: {item.reason}{size_suffix}")
            if not items:
                lines.append("  - none")
            lines.append("")
        lines.append(
            "Result: findings detected" if self.has_findings else "Result: no findings detected"
        )
        return "\n".join(lines)


def scan_path(target: Path, max_size_bytes: int) -> ScanResult:
    findings: list[Finding] = []
    total_files = 0

    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue

        total_files += 1
        relative_path = path.relative_to(target).as_posix()
        name = path.name
        parts = set(path.relative_to(target).parts)
        size_bytes = path.stat().st_size

        if is_secret_path(name):
            findings.append(Finding("secrets", relative_path, "secret-like filename", size_bytes))

        if is_private_path(name, parts):
            findings.append(
                Finding("private-files", relative_path, "private config or credential path", size_bytes)
            )

        if is_junk_path(name, parts):
            findings.append(Finding("junk-metadata", relative_path, "junk metadata artifact", size_bytes))

        if size_bytes > max_size_bytes:
            findings.append(Finding("large-files", relative_path, "exceeds configured size threshold", size_bytes))

    findings.sort(key=lambda finding: (CATEGORY_ORDER.index(finding.category), finding.path))
    return ScanResult(
        target=str(target),
        total_files=total_files,
        findings=findings,
        max_size_bytes=max_size_bytes,
    )


def is_secret_path(name: str) -> bool:
    return (
        name in SECRET_FILENAMES
        or name.startswith(".env.")
        or name.startswith("credentials")
        or name.endswith(SECRET_SUFFIXES)
    )


def is_private_path(name: str, parts: set[str]) -> bool:
    return name in PRIVATE_FILENAMES or bool(parts & PRIVATE_PATH_PARTS)


def is_junk_path(name: str, parts: set[str]) -> bool:
    return name in JUNK_FILENAMES or name.endswith(JUNK_SUFFIXES) or bool(parts & JUNK_PATH_PARTS)


def format_bytes(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size_bytes} B"
