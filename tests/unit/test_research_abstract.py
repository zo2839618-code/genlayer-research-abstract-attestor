from pathlib import Path

def test_contract_shape():
    text = (Path(__file__).parents[2] / 'contracts' / 'research_abstract_attestor.py').read_text(encoding='utf-8')
    assert 'gl.nondet.web.get' in text
    assert 'gl.nondet.exec_prompt' in text
    assert 'gl.vm.run_nondet_unsafe' in text
    assert '公开研究摘要' in text
