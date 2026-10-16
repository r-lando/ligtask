from app.services.secret_service import scan_secrets


def test_firebase_config_is_visible_info_not_silently_removed(tmp_path):
    (tmp_path / "config.js").write_text('''const firebaseConfig = {
apiKey: "SyntheticKeyValue123",
authDomain: "app.firebaseapp.com",
projectId: "app", appId: "app-id"
};
const password = "PrivatePassword123";
''')
    findings = scan_secrets(tmp_path)["findings"]
    assert any(f["rule_id"] == "firebase-browser-config" and f["severity"] == "INFO" for f in findings)
    assert any(f["rule_id"] == "generic-secret-assignment" and f["severity"] == "MEDIUM" for f in findings)
    assert "SyntheticKeyValue123" not in str(findings)


def test_api_key_without_full_firebase_context_stays_secret_candidate(tmp_path):
    (tmp_path / "config.js").write_text('const apiKey = "PrivateKeyValue123";')
    findings = scan_secrets(tmp_path)["findings"]
    assert findings[0]["rule_id"] == "generic-secret-assignment"
    assert findings[0]["severity"] == "MEDIUM"


def test_private_password_on_same_line_as_firebase_key_is_not_downgraded(tmp_path):
    (tmp_path / "config.js").write_text('''const firebaseConfig = {
apiKey: "SyntheticKeyValue123", password: "PrivatePassword123",
authDomain: "app.firebaseapp.com", projectId: "app", appId: "app-id"
};''')
    findings = scan_secrets(tmp_path)["findings"]
    assert len(findings) == 2
    assert all(f["rule_id"] == "generic-secret-assignment" and f["severity"] == "MEDIUM" for f in findings)
