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

import os
import json
import aiohttp
import zipfile
import zipstream


def export_project(project, include_images=False):
    """
    Export the project as zip. It's a ZipStream object.
    The file will be read chunk by chunk when you iterate on
    the zip.

    It will ignore some files like snapshots and

    :returns: ZipStream object
    """

    # To avoid issue with data not saved we disallow the export of a running topologie
    if project.is_running():
        raise aiohttp.web.HTTPConflict(text="Running topology could not be exported")

    z = zipstream.ZipFile()

    # First we process the .gns3 in order to be sure we don't have an error
    for file in os.listdir(project._path):
        if file.endswith(".gns3"):
            _export_project_file(project, os.path.join(project._path, file), z, include_images)

    for root, dirs, files in os.walk(project._path, topdown=True):
        # Remove snapshots and capture
        if os.path.split(root)[-1:][0] == "project-files":
            dirs[:] = [d for d in dirs if d not in ("snapshots", "tmp")]

        # Ignore log files and OS noise
        files = [f for f in files if not f.endswith('_log.txt') and not f.endswith('.log') and f != '.DS_Store']

        for file in files:
            path = os.path.join(root, file)
            # Try open the file
            try:
                open(path).close()
            except OSError as e:
                msg = "Could not export file {}: {}".format(path, e)
                log.warn(msg)
                project.emit("log.warning", {"message": msg})
                continue
        if file.endswith(".gns3"):
            pass
        else:
            z.write(path, os.path.relpath(path, project._path), compress_type=zipfile.ZIP_DEFLATED)
    return z


def _export_project_file(project, path, z, include_images):
    """
    Take a project file (.gns3) and patch it for the export

    We rename the .gns3 project.gns3 to avoid the task to the client to guess the file name

    :param path: Path of the .gns3
    """

    # Image file that we need to include in the exported archive
    images = set()

    with open(path) as f:
        topology = json.load(f)
    if "topology" in topology and "nodes" in topology["topology"]:
        for node in topology["topology"]["nodes"]:
            if node["node_type"] in ["virtualbox", "vmware", "cloud"]:
                raise aiohttp.web.HTTPConflict(text="Topology with a {} could not be exported".format(node["node_type"]))

            if "properties" in node and node["node_type"] != "Docker":
                for prop, value in node["properties"].items():
                    if prop.endswith("image"):
                        node["properties"][prop] = os.path.basename(value)
                        if include_images is True:
                            images.add(value)

    for image in images:
        _export_images(project, image, z)
    z.writestr("project.gns3", json.dumps(topology).encode())


def _export_images(project, image, z):
    """
    Take a project file (.gns3) and export images to the zip

    :param image: Image path
    :param z: Zipfile instance for the export
    """
    from ..compute import MODULES

    for module in MODULES:
        try:
            img_directory = module.instance().get_images_directory()
        except NotImplementedError:
            # Some modules don't have images
            continue

        directory = os.path.split(img_directory)[-1:][0]

        if os.path.exists(image):
            path = image
        else:
            path = os.path.join(img_directory, image)

        if os.path.exists(path):
            arcname = os.path.join("images", directory, os.path.basename(image))
            z.write(path, arcname)
            break