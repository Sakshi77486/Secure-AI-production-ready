from pathlib import Path
import shutil
import subprocess
import uuid

from app.config import settings


class RepositoryService:
    """Clone and prepare GitHub repositories for security scanning."""

    def __init__(self) -> None:
        self.base_dir = Path("temp/repositories")
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def clone_github_repository(self, repository_url: str) -> dict:
        """Clone a public GitHub repository into a temporary directory."""

        repository_id = str(uuid.uuid4())
        repository_path = self.base_dir / repository_id

        try:
            result = subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    repository_url,
                    str(repository_path),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    result.stderr.strip()
                    or "Git clone failed."
                )

            files = self._discover_source_files(repository_path)

            return {
                "repository_id": repository_id,
                "repository_path": str(repository_path),
                "repository_url": repository_url,
                "files": files,
                "files_count": len(files),
            }

        except subprocess.TimeoutExpired as exc:
            self._cleanup(repository_path)
            raise RuntimeError(
                "Repository cloning timed out."
            ) from exc

        except Exception:
            self._cleanup(repository_path)
            raise

    def _discover_source_files(
        self,
        repository_path: Path,
    ) -> list[str]:
        """
        Discover relevant source/configuration files.

        Generated directories, dependency folders and Git metadata
        are ignored.
        """

        ignored_directories = {
            ".git",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            "env",
            ".env",
            "dist",
            "build",
            ".next",
            ".nuxt",
            "coverage",
            ".pytest_cache",
            ".mypy_cache",
        }

        supported_extensions = {
            # Python
            ".py",

            # JavaScript / TypeScript
            ".js",
            ".jsx",
            ".ts",
            ".tsx",

            # Backend / compiled languages
            ".php",
            ".java",
            ".go",
            ".rs",
            ".c",
            ".cpp",
            ".h",
            ".hpp",

            # Database
            ".sql",

            # Configuration files useful for security analysis
            ".json",
            ".yaml",
            ".yml",
            ".toml",
            ".ini",
            ".xml",
        }

        files: list[str] = []

        for path in repository_path.rglob("*"):

            if not path.is_file():
                continue

            # Ignore unwanted directories anywhere in the path.
            if any(
                directory in ignored_directories
                for directory in path.parts
            ):
                continue

            # Ignore unsupported file types.
            if path.suffix.lower() not in supported_extensions:
                continue

            try:
                size_bytes = path.stat().st_size

                if size_bytes > settings.MAX_FILE_SIZE_KB * 1024:
                    continue

            except OSError:
                continue

            relative_path = path.relative_to(repository_path)

            files.append(str(relative_path))

            if len(files) >= settings.MAX_FILES_IN_REPOSITORY:
                break

        # Stable ordering makes scan results predictable.
        files.sort()

        return files

    def cleanup(self, repository_path: str) -> None:
        """Remove a cloned repository."""

        self._cleanup(Path(repository_path))

    @staticmethod
    def _cleanup(repository_path: Path) -> None:
        if repository_path.exists():
            shutil.rmtree(
                repository_path,
                ignore_errors=True,
            )


repository_service = RepositoryService()