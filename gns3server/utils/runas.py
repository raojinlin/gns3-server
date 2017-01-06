#!/usr/bin/env python
#
# Copyright (C) 2017 GNS3 Technologies Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import shlex
import pywintypes
import win32con
import win32event
import win32process
from win32com.shell.shell import ShellExecuteEx
from win32com.shell import shellcon

import logging
log = logging.getLogger(__name__)


def runas(*command, timeout=300):
    """
    Run a command as an administrator on Windows.
    """

    program = '"%s"' % command[0]
    params = " ".join(['"%s"' % (x,) for x in command[1:]])
    try:
        process = ShellExecuteEx(nShow=win32con.SW_SHOWNORMAL,
                                 fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                                 lpVerb="runas",
                                 lpFile=program,
                                 lpParameters=params)
    except pywintypes.error as e:
        command_string = " ".join(shlex.quote(s) for s in command)
        log.error('Could not execute command "{}": {}'.format(command_string, e), True)
        return False

    handle = process['hProcess']
    win32event.WaitForSingleObject(handle, timeout * 1000)
    return_code = win32process.GetExitCodeProcess(handle)
    if return_code != 0:
        log.error("Return code is {}".format(return_code), True)
        return False
    return True
