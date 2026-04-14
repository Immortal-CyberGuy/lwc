from src.crypto.aes_engine import AESEngine
from src.crypto.ascon_engine import AsconEngine
from src.crypto.present_engine import PresentEngine
from src.crypto.speck_engine import SpeckEngine


_ENGINE_FACTORIES = {
    "ascon": AsconEngine,
    "aes": AESEngine,
    "speck": SpeckEngine,
    "present": PresentEngine,
}


def available_engines() -> list[str]:
    return sorted(_ENGINE_FACTORIES.keys())


def create_engine(name: str):
    key = name.strip().lower()
    if key not in _ENGINE_FACTORIES:
        opts = ", ".join(available_engines())
        raise ValueError(f"Unsupported engine '{name}'. Available: {opts}")
    return _ENGINE_FACTORIES[key]()
