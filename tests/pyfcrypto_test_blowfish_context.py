#!/usr/bin/env python
#
# Python-bindings blowfish_context type test script
#
# Copyright (C) 2017-2024, Joachim Metz <joachim.metz@gmail.com>
#
# Refer to AUTHORS for acknowledgements.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import os
import sys
import unittest

import pyfcrypto


class BlowfishContextTypeTests(unittest.TestCase):
  """Tests the blowfish_context type."""

  def test_initialize(self):
    """Tests the __init__ function."""
    blowfish_context = pyfcrypto.blowfish_context()
    self.assertIsNotNone(blowfish_context)

  def test_set_key(self):
    """Tests the set_key function."""
    blowfish_context = pyfcrypto.blowfish_context()
    blowfish_context.set_key(b'0123')

    with self.assertRaises(ValueError):
      blowfish_context.set_key(None)

  def test_crypt_blowfish_cbc(self):
    """Tests the crypt_blowfish_cbc( function."""
    blowfish_context = pyfcrypto.blowfish_context()
    blowfish_context.set_key(b'This is a key123')

    encrypted_data = (
        b'}\x00\x99\xd2\xab\x1c\xcd\x80y\xef\x0b\x0f\xf72Rp\xbb\\h\x06\xff\x07'
        b'\x9a\xcfE\r\x8d\x18\x90\x8e\xfe\xa3')

    decrypted_data = pyfcrypto.crypt_blowfish_cbc(
        blowfish_context, pyfcrypto.crypt_modes.DECRYPT, b'This IV!',
        encrypted_data)

    self.assertEqual(decrypted_data, b'This is secret encrypted text!!!')

  def test_crypt_blowfish_ecb(self):
    """Tests the crypt_blowfish_ecb( function."""
    blowfish_context = pyfcrypto.blowfish_context()
    blowfish_context.set_key(b'test1')

    decrypted_data = pyfcrypto.crypt_blowfish_ecb(
        blowfish_context, pyfcrypto.crypt_modes.DECRYPT,
        b'\x11qMc\xe0m\xd7\x9e')

    self.assertEqual(decrypted_data, b'12345678')


if __name__ == "__main__":
  argument_parser = argparse.ArgumentParser()

  options, unknown_options = argument_parser.parse_known_args()
  unknown_options.insert(0, sys.argv[0])

  unittest.main(argv=unknown_options, verbosity=2)
