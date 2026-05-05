import unittest
from pathlib import Path

from cyberlab.brute_force import hash_password, run_dictionary_attack


class BruteForceTest(unittest.TestCase):
    def test_hash_is_stable(self):
        self.assertEqual(hash_password("senha123"), hash_password("senha123"))

    def test_finds_password_in_wordlist(self):
        temp_dir = Path(__file__).parent / ".tmp"
        temp_dir.mkdir(exist_ok=True)
        wordlist = temp_dir / "words.txt"
        wordlist.write_text("admin\nsenha123\n", encoding="utf-8")

        result = run_dictionary_attack("senha123", wordlist)

        self.assertTrue(result.found)
        self.assertEqual(result.password, "senha123")
        self.assertEqual(result.attempts, 2)


if __name__ == "__main__":
    unittest.main()
