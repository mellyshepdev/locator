"""Per-unit ingest keys: minting, verification, and the path scope a key grants."""
import os
import tempfile
import unittest

os.environ["UNIT_KEYS_FILE"] = os.path.join(tempfile.mkdtemp(), "unit_ingest_keys.json")
import unitkeys as U  # noqa: E402


class TestUnitKeys(unittest.TestCase):
    def test_mint_then_verify(self):
        key = U.mint("unit8")
        self.assertTrue(U.verify("unit8", key))

    def test_key_is_bound_to_its_unit(self):
        key = U.mint("unit8")
        U.mint("unit9")
        self.assertFalse(U.verify("unit9", key))

    def test_rotation_revokes_old_key(self):
        old = U.mint("unit7")
        new = U.mint("unit7")
        self.assertFalse(U.verify("unit7", old))
        self.assertTrue(U.verify("unit7", new))

    def test_wrong_or_missing_key(self):
        U.mint("unit4")
        self.assertFalse(U.verify("unit4", "lk_wrong"))
        self.assertFalse(U.verify("unit4", ""))
        self.assertFalse(U.verify("nobody", "lk_x"))

    def test_only_hash_is_stored(self):
        key = U.mint("unit3")
        with open(U.KEYS_FILE) as f:
            self.assertNotIn(key, f.read())
        self.assertEqual(os.stat(U.KEYS_FILE).st_mode & 0o777, 0o600)

    def test_listing_has_no_hashes(self):
        U.mint("unit5")
        self.assertNotIn("sha256", str(U.listing()))

    def test_invalid_unit_names(self):
        for bad in ("", "../x", "a/b", "unit 8", ".hidden"):
            with self.assertRaises(ValueError):
                U.mint(bad)

    def test_path_scope(self):
        ok = U.path_in_scope
        self.assertTrue(ok("compose/units/unit8/matomo", "compose", "unit8"))
        self.assertFalse(ok("compose/units/unit9/matomo", "compose", "unit8"))
        self.assertFalse(ok("compose/units/unit8", "compose", "unit8"))          # the prefix itself
        self.assertFalse(ok("compose/units/unit8/../unit9/x", "compose", "unit8"))
        self.assertFalse(ok("compose/units/unit80/x", "compose", "unit8"))       # prefix collision
        self.assertFalse(ok("compose/matomo", "compose", "unit8"))
        self.assertFalse(ok("ebay/production", "compose", "unit8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
