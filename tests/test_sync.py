import unittest

from sync import (
    IdentifierFormatter,
    SyncError,
    escape_scim_filter,
    parse_groups,
    validate_okta_domain,
    validate_scim_base_url,
)


class ValidationTests(unittest.TestCase):
    def test_okta_domain(self):
        self.assertEqual(
            validate_okta_domain("Example.okta.com"),
            "example.okta.com",
        )
        with self.assertRaises(SyncError):
            validate_okta_domain("https://example.okta.com/path")
        with self.assertRaises(SyncError):
            validate_okta_domain("example.com")

    def test_scim_url(self):
        value = "https://scim.eu-west-1.amazonaws.com/example/scim/v2/"
        self.assertEqual(validate_scim_base_url(value), value.rstrip("/"))
        with self.assertRaises(SyncError):
            validate_scim_base_url("http://example.test/scim/v2")

    def test_groups_are_trimmed_and_deduplicated(self):
        self.assertEqual(
            parse_groups(["alpha, beta", "alpha"]),
            ["alpha", "beta"],
        )
        with self.assertRaises(SyncError):
            parse_groups([" , "])

    def test_identifiers_are_hidden_by_default(self):
        formatter = IdentifierFormatter(False)
        rendered = formatter("person@example.com")
        self.assertTrue(rendered.startswith("sha256:"))
        self.assertNotIn("person", rendered)
        self.assertEqual(
            IdentifierFormatter(True)("person@example.com"),
            "person@example.com",
        )

    def test_scim_filter_escaping(self):
        self.assertEqual(
            escape_scim_filter('a"b\\c'),
            'a\\"b\\\\c',
        )


if __name__ == "__main__":
    unittest.main()
