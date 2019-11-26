#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019


class SamrError(Exception):
    pass


class DeleteEntityException(SamrError):
    pass


class ListEntitiesException(SamrError):
    pass


class CreateEntityException(SamrError):
    pass
