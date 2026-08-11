from auth import is_authenticated

def test_empty_token():
    assert is_authenticated("") is False
