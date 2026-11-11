# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

# Importing the submodule explicitly so that modules doing only an
# ``import aiocoap`` (eg. test_oscore.py) can access aiocoap.defaults even when
# pytest places the repository root at the front of sys.path, where the
# editable install's meta-path finder is not used for the package.
import aiocoap.defaults  # noqa: F401
