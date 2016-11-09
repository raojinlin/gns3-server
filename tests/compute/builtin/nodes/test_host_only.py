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

import uuid
import pytest
from unittest.mock import MagicMock
from tests.utils import asyncio_patch

from gns3server.compute.builtin.nodes.host_only import HostOnly


def test_json(on_gns3vm, project):
    host_only = HostOnly("host_only1", str(uuid.uuid4()), project, MagicMock())
    assert host_only.__json__() == {
        "name": "host_only1",
        "node_id": host_only.id,
        "project_id": project.id,
        "status": "started",
        "ports_mapping": [
            {
                'interface': 'virbr0',
                'name': 'host0',
                'port_number': 0,
                'type': 'ethernet'
            }
        ]
    }
