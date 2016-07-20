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

import pytest
import asyncio
import aiohttp
from unittest.mock import MagicMock
from tests.utils import asyncio_patch

from gns3server.controller.project import Project
from gns3server.controller.udp_link import UDPLink
from gns3server.controller.node import Node


@pytest.fixture
def project(controller):
    return Project(controller=controller, name="Test")


def test_create(async_run, project):
    compute1 = MagicMock()
    compute2 = MagicMock()

    node1 = Node(project, compute1, "node1", node_type="vpcs")
    node2 = Node(project, compute2, "node2", node_type="vpcs")

    link = UDPLink(project)
    async_run(link.add_node(node1, 0, 4))
    async_run(link.add_node(node2, 3, 1))

    @asyncio.coroutine
    def compute1_callback(path, data={}):
        """
        Fake server
        """
        if "/ports/udp" in path:
            response = MagicMock()
            response.json = {"udp_port": 1024}
            return response

    @asyncio.coroutine
    def compute2_callback(path, data={}):
        """
        Fake server
        """
        if "/ports/udp" in path:
            response = MagicMock()
            response.json = {"udp_port": 2048}
            return response

    compute1.post.side_effect = compute1_callback
    compute1.host = "example.com"
    compute2.post.side_effect = compute2_callback
    compute2.host = "example.org"
    async_run(link.create())

    compute1.post.assert_any_call("/projects/{}/vpcs/nodes/{}/adapters/0/ports/4/nio".format(project.id, node1.id), data={
        "lport": 1024,
        "rhost": compute2.host,
        "rport": 2048,
        "type": "nio_udp"
    })
    compute2.post.assert_any_call("/projects/{}/vpcs/nodes/{}/adapters/3/ports/1/nio".format(project.id, node2.id), data={
        "lport": 2048,
        "rhost": compute1.host,
        "rport": 1024,
        "type": "nio_udp"
    })


def test_delete(async_run, project):
    compute1 = MagicMock()
    compute2 = MagicMock()

    node1 = Node(project, compute1, "node1", node_type="vpcs")
    node2 = Node(project, compute2, "node2", node_type="vpcs")

    link = UDPLink(project)
    async_run(link.add_node(node1, 0, 4))
    async_run(link.add_node(node2, 3, 1))

    async_run(link.delete())

    compute1.delete.assert_any_call("/projects/{}/vpcs/nodes/{}/adapters/0/ports/4/nio".format(project.id, node1.id))
    compute2.delete.assert_any_call("/projects/{}/vpcs/nodes/{}/adapters/3/ports/1/nio".format(project.id, node2.id))


def test_choose_capture_side(async_run, project):
    """
    The link capture should run on the optimal node
    """
    compute1 = MagicMock()
    compute2 = MagicMock()
    compute2.id = "local"

    node_vpcs = Node(project, compute1, "node1", node_type="vpcs")
    node_iou = Node(project, compute2, "node2", node_type="iou")

    link = UDPLink(project)
    async_run(link.add_node(node_vpcs, 0, 4))
    async_run(link.add_node(node_iou, 3, 1))

    assert link._choose_capture_side()["node"] == node_iou

    node_vpcs = Node(project, compute1, "node3", node_type="vpcs")
    node_vpcs2 = Node(project, compute1, "node4", node_type="vpcs")

    link = UDPLink(project)
    async_run(link.add_node(node_vpcs, 0, 4))
    async_run(link.add_node(node_vpcs2, 3, 1))

    # Capture should run on the local node
    node_iou = Node(project, compute1, "node5", node_type="iou")
    node_iou2 = Node(project, compute2, "node6", node_type="iou")

    link = UDPLink(project)
    async_run(link.add_node(node_iou, 0, 4))
    async_run(link.add_node(node_iou2, 3, 1))

    assert link._choose_capture_side()["node"] == node_iou2


def test_capture(async_run, project):
    compute1 = MagicMock()

    node_vpcs = Node(project, compute1, "V1", node_type="vpcs")
    node_iou = Node(project, compute1, "I1", node_type="iou")

    link = UDPLink(project)
    async_run(link.add_node(node_vpcs, 0, 4))
    async_run(link.add_node(node_iou, 3, 1))

    capture = async_run(link.start_capture())
    assert link.capturing

    compute1.post.assert_any_call("/projects/{}/vpcs/nodes/{}/adapters/0/ports/4/start_capture".format(project.id, node_vpcs.id), data={
        "capture_file_name": link.default_capture_file_name(),
        "data_link_type": "DLT_EN10MB"
    })

    capture = async_run(link.stop_capture())
    assert link.capturing is False

    compute1.post.assert_any_call("/projects/{}/vpcs/nodes/{}/adapters/0/ports/4/stop_capture".format(project.id, node_vpcs.id))


def test_read_pcap_from_source(project, async_run):
    compute1 = MagicMock()

    link = UDPLink(project)
    async_run(link.add_node(compute1, 0, 4))
    async_run(link.add_node(compute1, 3, 1))

    capture = async_run(link.start_capture())
    assert link._capture_node is not None

    async_run(link.read_pcap_from_source())
    link._capture_node["node"].compute.steam_file.assert_called_with(project, "tmp/captures/" + link._capture_file_name)