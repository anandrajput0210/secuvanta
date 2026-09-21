import unittest

from core.entropy import calculate_entropy, is_high_entropy


class TestEntropy(unittest.TestCase):

    def test_empty_string(self):
        self.assertEqual(calculate_entropy(""), 0.0)

    def test_low_entropy(self):
        value = "aaaaaaaaaaaaaaaaaaaa"
        entropy = calculate_entropy(value)

        self.assertLess(entropy, 1.0)

    def test_high_entropy(self):
        value = "aK9#mP2$xL7@qR4!vN8*zT5&wY1"

        self.assertTrue(is_high_entropy(value))


if __name__ == "__main__":
    unittest.main()