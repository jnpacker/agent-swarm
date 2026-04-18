from swarmer.agent_tools.opencode import OpenCodeStrategy
from swarmer.config import settings


class PythonStrategy(OpenCodeStrategy):

    @property
    def name(self) -> str:
        return "opencode-python"

    @property
    def display_name(self) -> str:
        return "OpenCode (Python)"

    def get_image(self) -> str:
        return settings.agent_image_python
