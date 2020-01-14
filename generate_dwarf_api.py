"""
    Dwarf - Copyright (C) 2018-2020 Giovanni Rocca (iGio90)

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

"""
    TODO:   read public functions in api.ts make it python and use /src/py/dwarf_api_skeleton.py to create
            /dist/dwarf_api.py wich replaces dwarf_debugger/core/dwarf_api.py

            ex:

            from /src/api.ts

            public addObserveLocation = (name: string, npAddress: NativePointer | string, watchType: string, watchMode: string, handler: string | Function, bytesLength:number = 0)

            becomes in /dist/dwarf_api.py

            def addObserveLocation(self, name: str, npAddress, watchType: str, watchMode: str, handler, bytesLength: int = 0):

                self._dwarf_core._api_call('addObserveLocation', [
                    name, npAddress, watchType, watchMode, handler,
                    bytesLength
                ])
"""