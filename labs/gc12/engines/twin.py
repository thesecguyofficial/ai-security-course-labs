"""The offline Model Armor twin (armor_twin.py) behind the engine interface. $0, no network."""

import armor_twin


class TwinEngine:
    name = "twin (offline stand-in)"

    def __init__(self, template: dict, available: bool = True, **_):
        self.template, self.available = template, available

    def sanitize_user_prompt(self, text: str) -> dict:
        return armor_twin.sanitize_user_prompt(self.template, text, available=self.available)

    def sanitize_model_response(self, text: str, user_prompt: str = "") -> dict:
        return armor_twin.sanitize_model_response(self.template, text, user_prompt, available=self.available)
