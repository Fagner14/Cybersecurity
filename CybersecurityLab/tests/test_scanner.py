import unittest

from cyberlab.scanner import parse_ports


class ParsePortsTest(unittest.TestCase):
    def test_parses_ranges_and_values(self):
        self.assertEqual(parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])

    def test_rejects_invalid_range(self):
        with self.assertRaises(ValueError):
            parse_ports("100-90")

    def test_rejects_out_of_range_port(self):
        with self.assertRaises(ValueError):
            parse_ports("0")


if __name__ == "__main__":
    unittest.main()
