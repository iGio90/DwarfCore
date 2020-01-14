"""
    Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.
    If not, see <https://www.gnu.org/licenses/>
"""

from PyQt5.QtCore import QObject

from dwarf_debugger.utils import is_core

# pylint: disable=missing-docstring
# pylint: disable=invalid-name
# pylint: disable=protected-access


class DwarfApi(QObject):
    def __init__(self, dwarf_core):
        super().__init__()

        if not is_core(dwarf_core):
            raise Exception('No DwarfCore')

        self.setObjectName('DwarfApi')

        self._dwarf_core = dwarf_core

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
