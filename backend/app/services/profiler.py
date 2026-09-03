from collections import Counter
from pathlib import Path


LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".php": "PHP",
    ".html": "HTML",
    ".css": "CSS",
}

DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "composer.json",
    "composer.lock",
}

CONFIG_FILES = {
    ".env",
    ".env.example",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "nginx.conf",
    "web.config",
}


def profile_repository(repository_path: Path):
    language_counts = Counter()
    dependency_files = []
    config_files = []
    total_files = 0

    for path in repository_path.rglob("*"):
        if not path.is_file():
            continue

        total_files += 1

        extension = path.suffix.lower()
        filename = path.name.lower()

        # Detect programming/web languages
        language = LANGUAGE_EXTENSIONS.get(extension)

        if language:
            language_counts[language] += 1

        # Detect dependency files
        if filename in DEPENDENCY_FILES:
            dependency_files.append(
                str(path.relative_to(repository_path))
            )

        # Detect configuration files
        if filename in CONFIG_FILES:
            config_files.append(
                str(path.relative_to(repository_path))
            )

    return {
        "total_files": total_files,
        "languages": dict(language_counts),
        "dependency_files": dependency_files,
        "configuration_files": config_files,
    }