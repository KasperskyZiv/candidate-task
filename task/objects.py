#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019

# Standard packages
from dataclasses import dataclass

# External packages
from impacket.dcerpc.v5.samr import SAMPR_USER_ALL_INFORMATION, SAMPR_ALIAS_GENERAL_INFORMATION


@dataclass
class User:
    user_name: str
    uid: int
    user_data: SAMPR_USER_ALL_INFORMATION = None

    def __eq__(self, other):
        return self.user_name == other.user_name and self.uid == other.uid


@dataclass
class Group:
    group_name: str
    gid: int
    user_data: SAMPR_ALIAS_GENERAL_INFORMATION = None

    def __eq__(self, other):
        return self.group_name == other.group_name and self.gid == other.gid


@dataclass
class Target:
    domain: str
    username: str
    password: str
    remote_name: str
