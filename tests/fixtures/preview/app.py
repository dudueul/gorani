"""Count the deer."""

from dataclasses import dataclass


@dataclass
class Site:
    name: str
    count: int


def total(sites: list[Site]) -> int:
    # 고라니, counted
    return sum(s.count for s in sites)


if __name__ == "__main__":
    print(total([Site("North ridge", 12), Site("강가", 7)]))
