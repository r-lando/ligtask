from copy import deepcopy
import pytest
from app.services.enrichment_service import enrich_finding, TARGETED_RULES, TARGETED_GUIDANCE


@pytest.mark.parametrize('rule', list(TARGETED_RULES))
@pytest.mark.parametrize('prefix', ['', 'backend.'])
def test_targeted_guidance_preserves_evidence(rule, prefix):
    original = {'rule_id': prefix + rule, 'category': 'SAST', 'scanner': 'Semgrep',
                'message': 'Original scanner evidence.', 'severity': 'HIGH', 'file': 'route.js',
                'line': 12, 'source_rule_ids': ['one', 'two'], 'evidence_count': 2}
    before = deepcopy(original)
    result = enrich_finding(original)
    assert original == before
    for key, value in original.items():
        assert result[key] == value
    assert result['description'] == original['message']
    assert result['guidance_source'] == 'TALGED Rule Guidance'
    assert 'This scan has not tested a deployed attack.' in result['recommendation']
    assert 'Review the flagged code and fix the unsafe pattern.' != result['recommended_action']


@pytest.mark.parametrize('rule,category', [('unknown-sql-rule', 'SAST'),
    ('foreign.request-to-shell-exec', 'SAST'), ('overlapping-eval-warnings', 'DEPENDENCY')])
def test_unrelated_findings_do_not_receive_targeted_fixes(rule, category):
    result = enrich_finding({'rule_id': rule, 'category': category, 'message': 'SQL eval shell'})
    assert result['recommendation'] not in {g['recommendation'] for g in TARGETED_GUIDANCE.values()}
