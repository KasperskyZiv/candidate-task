#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019

# Standard packages
from dataclasses import dataclass

# External packages
from impacket.dcerpc.v5.samr import SAMPR_USER_ALL_INFORMATION, SAMPR_ALIAS_GENERAL_INFORMATION


@dataclass
class Entity:
    name: str
    uniq_id: int

    def __eq__(self, other):
        return (self.uniq_id, self.name, type(self)) == (other.uniq_id, other.name, type(other))


@dataclass(eq=False)
class User(Entity):
    data: SAMPR_USER_ALL_INFORMATION = None


@dataclass(eq=False)
class Group(Entity):
    data: SAMPR_ALIAS_GENERAL_INFORMATION = None


@dataclass(eq=False)
class Alias(Entity):
    data: SAMPR_ALIAS_GENERAL_INFORMATION = None


@dataclass
class Target:
    domain: str
    username: str
    password: str
    remote_name: str
