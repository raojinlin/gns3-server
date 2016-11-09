#!/usr/bin/env python
#
# Copyright (C) 2016 GNS3 Technologies Inc.
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
from .cloud import Cloud
from ...error import NodeError

import gns3server.utils.interfaces


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
