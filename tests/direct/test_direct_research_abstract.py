from pathlib import Path

def test_direct_smoke_shape():
    root = Path(__file__).parents[2]
    assert (root / 'contracts').is_dir()
    assert (root / 'README.md').is_file()
