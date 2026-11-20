#!/usr/bin/env python3
#
# Copyright (C) 2026 flyinghead
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

CONFDIR = "/usr/local/etc/dcnet"
CONF_FILE = CONFDIR + "/discord.conf"
Config = {}
webhook = ""
initialized = False

def readConfig():
    try:
        with open(CONF_FILE) as myfile:
            for line in myfile:
                if line.strip().startswith(tuple(['#', ';'])):
                    continue
                name, var = line.partition("=")[::2]
                name = name.strip()
                var = var.strip()
                if name == "":
                    continue
                values = var.split(",")
                for i in range(0, len(values)):
                    values[i] = values[i].strip()
                Config[name] = values
    except FileNotFoundError:
        print("discord.conf file not found, disabling Discord notifications")

def init():
    global webhook, initialized
    if initialized:
        return
    initialized = True
    readConfig()
    disabled = Config.get("disabled-games", [])
    if "framegride" in disabled:
        return
    webhook = Config.get("webhook", [""])[0]

def postWebhook(body):
    import requests
    headers = {
        "Content-Type": "application/json"
    }
    requests.post(webhook, headers=headers, json=body)


def escape(text):
    """Escape Discord special/markdown characters by prefixing with a backslash.

    This prevents formatting, pings, and other markdown behaviour when sending
    user-provided text to Discord.
    """
    if text is None:
        return ""
    s = str(text)
    # Escape backslash first to avoid double-escaping later characters
    s = s.replace("\\", "\\\\")
    for ch in ('*', '_', '~', '`', '<', '>', ':', '[', '@', '|'):
        s = s.replace(ch, "\\" + ch)
    return s

def notification(content, embedTitle, embedText):
    init()
    if (webhook == "") or (webhook is None):
        return
    notif = {
        "content": content,
        "embeds": [
            {
                "author": {
                    "name": "Frame Gride",
                    "icon_url": "https://dcnet.flyca.st/gamepic/framegride.jpg"
                },
                "title": embedTitle,
                "description": embedText,
                "color": 9118205
            }
        ]
    }
    postWebhook(notif)
