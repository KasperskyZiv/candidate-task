#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019

# Standard packages
from dataclasses import dataclass

# External packages
from impacket.dcerpc.v5.samr import SAMPR_USER_ALL_INFORMATION, SAMPR_ALIAS_GENERAL_INFORMATION


@dataclass
class User:
    name: str
    uid: int
    user_data: SAMPR_USER_ALL_INFORMATION = None

    def __eq__(self, other):
        return self.name == other.name and self.uid == other.uid

@dataclass
class Group:
    name: str
    gid: int
    user_data: SAMPR_ALIAS_GENERAL_INFORMATION = None

    def __eq__(self, other):
        return self.name == other.name and self.gid == other.gid

@dataclass
class Alias:
    name: str
    aid: int
    user_data: SAMPR_ALIAS_GENERAL_INFORMATION = None

    def __eq__(self, other):
        return self.name == other.name and self.aid == other.aid


@dataclass
class Target:
    domain: str
    username: str
    password: str
    remote_name: str
