from swarmer.agent_tools import AgentToolStrategy

_REGISTRY: dict[str, AgentToolStrategy] = {}


def register(strategy: AgentToolStrategy) -> None:
    _REGISTRY[strategy.name] = strategy


def get(name: str) -> AgentToolStrategy:
    if name not in _REGISTRY:
        raise ValueError(
            f"Unknown agent tool: {name!r}. Available: {list(_REGISTRY)}"
        )
    return _REGISTRY[name]


def all_tools() -> list[AgentToolStrategy]:
    return list(_REGISTRY.values())


def _init() -> None:
    from swarmer.agent_tools.opencode import OpenCodeStrategy  # noqa: F811
    from swarmer.agent_tools.crush import CrushStrategy  # noqa: F811
    register(OpenCodeStrategy())
    register(CrushStrategy())


_init()
