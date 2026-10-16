from app.services.finding_context import file_context, context_summary
from app.services.secret_service import scan_line
import pytest


def test_context_is_path_based_and_keeps_all_counts():
    paths = ["src/auth.py", "evaluation/secret/create_fixtures.py",
             "backend/tests/test_auth.py", r"backend\semgrep_rules\rule.yaml"]
    assert [file_context(p) for p in paths] == [
        "Application / other", "Test / fixture", "Test / fixture", "Scanner rule"]
    assert context_summary([{"file": p} for p in paths]) == {
        "Application / other": 1, "Test / fixture": 2, "Scanner rule": 1}


def test_secret_annotation_is_not_a_credential():
    assert not scan_line('password: SecretStr = Field(min_length=1)', 1, 'auth.py')
    assert not scan_line('password: Optional[str] = None', 1, 'auth.py')


def test_literal_secrets_still_detected_including_typed_defaults():
    for line in ['password = "superprivate123"', 'password: str = "superprivate123"',
                 'password: SecretStr = "superprivate123"', '"password": "superprivate123"']:
        assert scan_line(line, 1, 'auth.py'), line


@pytest.mark.parametrize("line", [
    '"password": body.password.get_secret_value(),',
    '"secret": secret_status,',
    'password = runtime_password',
    'password = get_password()',
    'password: SecretStr = Field(min_length=1)',
    'const password = runtimePassword;',
    'const password = `${runtimePassword}`;',
    'password = "${PASSWORD_VALUE}"',
])
def test_runtime_references_are_not_literal_secrets(line):
    assert not scan_line(line, 1, "auth.py")


@pytest.mark.parametrize("path,line", [
    ("settings.py", 'password: str = "SuperPrivate123"'),
    ("settings.ts", 'const password = "SuperPrivate123";'),
    ("settings.json", '"password": "SuperPrivate123",'),
    ("settings.yaml", 'password: SuperPrivate123'),
    (".env", 'PASSWORD=SuperPrivate123'),
    (".env.production", 'PASSWORD=SuperPrivate123 # config'),
    ("settings.txt", 'password=SuperPrivate123'),
])
def test_supported_literal_formats_remain_detected(path, line):
    findings = scan_line(line, 1, path)
    assert any(f["rule_id"] == "generic-secret-assignment" for f in findings)
    assert "SuperPrivate123" not in str(findings)
