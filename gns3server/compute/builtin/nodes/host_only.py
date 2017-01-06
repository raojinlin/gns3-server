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

import sys
import asyncio
import shutil
from .cloud import Cloud
from ...error import NodeError

import logging
log = logging.getLogger(__name__)

import gns3server.utils.interfaces
from gns3server.utils.asyncio import wait_run_in_executor


class HostOnly(Cloud):
    """
    A portable and preconfigured node allowing topology to get
    a host only connection à la VMware or VirtualBox
    """

    def __init__(self, *args, **kwargs):
        ports = [
            {
                "name": "host0",
                "type": "ethernet",
                "interface": "virbr0",
                "port_number": 0
            }
        ]
        super().__init__(*args, ports=ports)

    def __json__(self):
        return {
            "name": self.name,
            "node_id": self.id,
            "project_id": self.project.id,
            "status": "started",
            "ports_mapping": self.ports_mapping
        }

    @asyncio.coroutine
    def create(self):
        """
        Creates this host-only node.
        """

        if sys.platform.startswith("win"):
            gns3loopback = shutil.which("gns3loopback")
            if gns3loopback is None:
                raise NodeError("Could not find gns3loopback.exe")
            yield from self._add_loopback(gns3loopback, "Host-Only-{}".format(self.id))
        super().create()
        log.info('Host-Only node "{name}" [{id}] has been created'.format(name=self._name, id=self._id))

    @asyncio.coroutine
    def _add_loopback(self, gns3loopback, name):
        """
        Add a Windows loopback adapter.
        """

        from gns3server.utils.runas import runas
        yield from wait_run_in_executor(runas, gns3loopback, '--add "{}" 10.42.1.1 255.0.0.0'.format(name))
