import pytest

from src.network.engine_factory import available_engines, create_engine


def test_available_engines_contains_expected_names():
    names = available_engines()
    assert "ascon" in names
    assert "aes" in names
    assert "speck" in names
    assert "present" in names


@pytest.mark.parametrize("name", ["ascon", "aes", "speck", "present", "ASCON"])
def test_create_engine(name):
    engine = create_engine(name)
    assert hasattr(engine, "encrypt")
    assert hasattr(engine, "decrypt")
    assert hasattr(engine, "name")


def test_create_engine_invalid():
    with pytest.raises(ValueError):
        create_engine("unknown-engine")
