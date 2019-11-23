#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019

# Standard packages
from dataclasses import dataclass

# External packages
from impacket.dcerpc.v5.samr import SAMPR_USER_ALL_INFORMATION

@dataclass
class User:
    username: str
    uid: int
    user_data: SAMPR_USER_ALL_INFORMATION
