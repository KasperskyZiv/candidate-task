#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019


class SamrError(Exception):
    pass

class ListUsersException(SamrError):
    pass

class AddUserException(SamrError):
    pass