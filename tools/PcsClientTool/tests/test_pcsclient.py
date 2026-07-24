#!/usr/bin/env python3
# encoding: utf-8

#
# Copyright(c) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import argparse
import unittest
from unittest.mock import patch
from pcsclient import Utils


class TestUtils(unittest.TestCase):
    def test_check_expire_hours_accepts_valid_values(self):
        self.assertEqual(Utils.check_expire_hours("0"), 0)
        self.assertEqual(Utils.check_expire_hours("24"), 24)
        self.assertEqual(Utils.check_expire_hours("8760"), 8760)

    def test_check_expire_hours_rejects_non_integer(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "abc is not a valid integer"):
            Utils.check_expire_hours("abc")

    def test_check_expire_hours_rejects_out_of_range_values(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "-1 is not in the range \\[0, 8760\\]"):
            Utils.check_expire_hours("-1")

        with self.assertRaisesRegex(argparse.ArgumentTypeError, "8761 is not in the range \\[0, 8760\\]"):
            Utils.check_expire_hours("8761")

    def test_check_qe_id_accepts_valid_hex_string(self):
        self.assertIsNone(Utils.check_qe_id("A1" * 16))

    def test_check_qe_id_rejects_invalid_length(self):
        with self.assertRaisesRegex(ValueError, r"^Invalid qe_id 'A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1' - expected exactly 32 hexadecimal characters \(16 bytes\)$"):
            Utils.check_qe_id("A1" * 15)

    def test_check_qe_id_rejects_non_hex_characters(self):
        with self.assertRaisesRegex(ValueError, r"^Invalid qe_id 'GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG' - expected exactly 32 hexadecimal characters \(16 bytes\)$"):
            Utils.check_qe_id("G" * 32)

    def test_check_qe_id_rejects_non_string_value(self):
        with self.assertRaisesRegex(ValueError, r"^Invalid qe_id None - expected exactly 32 hexadecimal characters \(16 bytes\)$"):
            Utils.check_qe_id(None)

    def test_check_pce_id_accepts_valid_hex_string(self):
        self.assertIsNone(Utils.check_pce_id("a1F0"))

    def test_check_pce_id_rejects_invalid_length(self):
        with self.assertRaisesRegex(ValueError, r"^Invalid pce_id 'abc' - expected exactly 4 hexadecimal characters \(2 bytes\)$"):
            Utils.check_pce_id("abc")

    def test_check_pce_id_rejects_non_hex_characters(self):
        with self.assertRaisesRegex(ValueError, r"^Invalid pce_id 'zzzz' - expected exactly 4 hexadecimal characters \(2 bytes\)$"):
            Utils.check_pce_id("zzzz")

    def test_check_pce_id_rejects_non_string_value(self):
        with self.assertRaisesRegex(ValueError, r"^Invalid pce_id 1234 - expected exactly 4 hexadecimal characters \(2 bytes\)$"):
            Utils.check_pce_id(1234)

    def test_check_file_writable_returns_true_when_file_does_not_exist(self):
        with patch("os.getcwd", return_value="/tmp"), \
                patch("os.path.isfile", return_value=False):
            self.assertTrue(Utils.check_file_writable("out.json"))

    def test_check_file_writable_returns_true_when_user_confirms_overwrite(self):
        with patch("os.getcwd", return_value="/tmp"), \
                patch("os.path.isfile", return_value=True), \
                patch("builtins.input", side_effect=["maybe", "y"]):
            self.assertTrue(Utils.check_file_writable("out.json"))

    def test_check_file_writable_returns_false_when_user_rejects_overwrite(self):
        with patch("os.getcwd", return_value="/tmp"), \
                patch("os.path.isfile", return_value=True), \
                patch("builtins.input", return_value="n"), \
                patch("builtins.print") as mock_print:
            self.assertFalse(Utils.check_file_writable("out.json"))
            mock_print.assert_called_with("Aborted.")

    def test_get_api_version_from_url_returns_default_when_missing(self):
        self.assertEqual(Utils.get_api_version_from_url("https://example.com/sgx/certification/"), 4)

    def test_get_api_version_from_url_extracts_version(self):
        self.assertEqual(Utils.get_api_version_from_url("https://example.com/sgx/certification/v4/"), 4)
        self.assertEqual(Utils.get_api_version_from_url("https://example.com/sgx/certification/v12/"), 12)


if __name__ == "__main__":
    unittest.main()