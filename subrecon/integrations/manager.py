"""Central manager for external reconnaissance tools."""

import os
import re
import shutil
import subprocess

from pathlib import Path

from subrecon.integrations.base import ToolCheckResult


TOOL_VERSION_ARGS = {
    "subfinder": ("-version",),
    "amass": ("-version",),
    "dnsx": ("-version",),
    "httpx": ("-version",),
    "katana": ("-version",),
    "nuclei": ("-version",),
}

PROJECTDISCOVERY_MARKERS = {
    "httpx": ("current version", "projectdiscovery"),
}


class ToolManager:
    """Detect and verify installed external tools."""

    def __init__(
        self,
        tool_paths: dict[str, str] | None = None,
        version_timeout: float = 5.0,
    ):
        self.tool_paths = tool_paths or {}
        self.version_timeout = version_timeout

    def _resolve_executable(self, tool_name: str) -> str | None:
        """Find an executable without launching it."""

        if tool_name in self.tool_paths:
            candidate = Path(self.tool_paths[tool_name]).expanduser()

            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)

            return None

        if tool_name == "amass":
            configured = os.getenv("SUBRECON_AMASS_BINARY")

            candidates = []

            if configured:
                candidates.append(Path(configured).expanduser())

            candidates.append(Path("/usr/lib/amass/amass"))

            for candidate in candidates:
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return str(candidate)

        return shutil.which(tool_name)

    def check_tool(self, tool_name: str) -> ToolCheckResult:
        """Check executable availability and verify its version."""

        if tool_name not in TOOL_VERSION_ARGS:
            raise ValueError(f"Unsupported tool: {tool_name}")

        executable = self._resolve_executable(tool_name)

        if executable is None:
            return ToolCheckResult(
                tool_name=tool_name,
                available=False,
                detail="Executable not found or not executable.",
            )

        # Never launch a known Amass shell wrapper.
        if tool_name == "amass":
            try:
                with open(executable, "rb") as file:
                    header = file.read(2)

                if header == b"#!":
                    return ToolCheckResult(
                        tool_name=tool_name,
                        available=False,
                        executable=executable,
                        detail="Amass shell wrapper detected; refusing to launch it.",
                    )
            except OSError as exc:
                return ToolCheckResult(
                    tool_name=tool_name,
                    available=False,
                    executable=executable,
                    detail=str(exc),
                )

        command = [
            executable,
            *TOOL_VERSION_ARGS[tool_name],
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.version_timeout,
                check=False,
                shell=False,
            )

        except subprocess.TimeoutExpired:
            return ToolCheckResult(
                tool_name=tool_name,
                available=False,
                executable=executable,
                detail="Version check timed out.",
            )

        except OSError as exc:
            return ToolCheckResult(
                tool_name=tool_name,
                available=False,
                executable=executable,
                detail=str(exc),
            )

        output = "\n".join(
            part for part in (result.stdout, result.stderr) if part
        )

        # Verify that HTTPx is ProjectDiscovery HTTPx, not Python HTTPX.
        markers = PROJECTDISCOVERY_MARKERS.get(tool_name, ())

        if markers:
            output_lower = output.lower()

            if not any(marker in output_lower for marker in markers):
                return ToolCheckResult(
                    tool_name=tool_name,
                    available=False,
                    executable=executable,
                    detail="Executable is not verified as ProjectDiscovery HTTPx.",
                )

        if result.returncode != 0:
            return ToolCheckResult(
                tool_name=tool_name,
                available=False,
                executable=executable,
                detail="Version check failed: " + output.strip(),
            )

        if not output.strip():
            return ToolCheckResult(
                tool_name=tool_name,
                available=False,
                executable=executable,
                detail="Version command returned no output.",
            )

        version_match = re.search(
            r"\bv?(\d+\.\d+(?:\.\d+)?)\b",
            output,
        )

        version = (
            version_match.group(1)
            if version_match
            else None
        )

        return ToolCheckResult(
            tool_name=tool_name,
            available=True,
            executable=executable,
            version=version,
            detail="Executable and version check successful.",
        )

    def check_all(self) -> dict[str, ToolCheckResult]:
        """Check all supported external tools."""

        return {
            name: self.check_tool(name)
            for name in TOOL_VERSION_ARGS
        }
