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
# pylint: disable=line-too-long

import os


def change_theme_css():
    """ replace fontsize in theme css
    """
    if not os.path.exists('./node_modules/eledoc/bin/default/assets/css/main.css'):
        print('theme css missing')
        return

    with open('./node_modules/eledoc/bin/default/assets/css/main.css', 'r+', encoding='utf8') as theme_file:
        theme_css = theme_file.read()
        theme_css = theme_css.replace(
            'font-size: 20px;', 'font-size: 100%;')
        theme_file.write(theme_css)
        theme_file.close()


if __name__ == '__main__':
    change_theme_css()
