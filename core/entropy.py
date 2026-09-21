import math
from collections import Counter


def calculate_entropy(value: str) -> float:
    """
    Calculate Shannon entropy for a string.

    Higher entropy can indicate a randomly generated token,
    password, or secret.
    """

    if not value:
        return 0.0

    length = len(value)

    frequencies = Counter(value)

    entropy = 0.0

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def is_high_entropy(value: str, threshold: float = 4.0) -> bool:
    """
    Check whether a string has suspiciously high entropy.
    """

    if len(value) < 20:
        return False

    return calculate_entropy(value) >= threshold