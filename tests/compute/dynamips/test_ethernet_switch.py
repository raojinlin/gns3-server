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

from tests.utils import AsyncioMagicMock
from gns3server.compute.dynamips.nodes.ethernet_switch import EthernetSwitchConsole


def test_arp_command(async_run):
    node = AsyncioMagicMock()
    node.name = "Test"
    node._hypervisor.send = AsyncioMagicMock(return_value=["0050.7966.6801  1  nio1", "0050.7966.6802  1  nio2"])
    console = EthernetSwitchConsole(node)
    assert async_run(console.arp()) == \
        "Mac                VLAN\n" \
        "00:50:79:66:68:01  1\n" \
        "00:50:79:66:68:02  1\n"
    node._hypervisor.send.assert_called_with("ethsw show_mac_addr_table Test")
