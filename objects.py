#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019

# Standard packages
from dataclasses import dataclass, field

# External packages
from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.samr import SAMPR_USER_ALL_INFORMATION, SAMPR_ALIAS_GENERAL_INFORMATION, \
    SAMPR_GROUP_GENERAL_INFORMATION


@dataclass
class Entity:
    name: str
    uniq_id: int
    metadata: object = field(repr=False)

    def __eq__(self, other):
        return (self.uniq_id, self.name, type(self)) == (other.uniq_id, other.name, type(other))

    @staticmethod
    def create(dce, domain_handle, name) -> 'Entity':
        pass

    @staticmethod
    def delete(dce, entity_handel, uniq_id):
        pass

    @staticmethod
    def filter_out_domain(domain_name: str) -> bool:
        return False

    @staticmethod
    def get_entity(dce, domain_handle, uniq_id) -> 'Entity':
        pass

    @staticmethod
    def enumerate(dce, domain_handle):
        pass


@dataclass(eq=False)
class User(Entity):
    metadata: SAMPR_USER_ALL_INFORMATION = field(repr=False, default=None)

    @staticmethod
    def delete(dce, domain_handle, uniq_id):
        entity_handel = samr.hSamrOpenUser(dce, domain_handle, userId=uniq_id)['UserHandle']
        samr.hSamrDeleteUser(dce, entity_handel)

    @staticmethod
    def create(dce, domain_handle, name):
        resp = samr.hSamrCreateUser2InDomain(dce, domain_handle, name)
        return User(name, resp['RelativeId'])

    @staticmethod
    def filter_out_domain(domain_name: str) -> bool:
        return domain_name == "Builtin"

    @staticmethod
    def get_entity(dce, domain_handle, samr_obj):
        resp = samr.hSamrOpenUser(dce, domain_handle, userId=samr_obj['RelativeId'])
        info = samr.hSamrQueryInformationUser2(dce, resp['UserHandle'],
                                               samr.USER_INFORMATION_CLASS.UserAllInformation)
        user = User(samr_obj['Name'], samr_obj['RelativeId'], info['Buffer']['All'])
        samr.hSamrCloseHandle(dce, resp['UserHandle'])
        return user

    @staticmethod
    def enumerate(dce, domain_handle):
        return samr.hSamrEnumerateUsersInDomain(dce, domain_handle)


@dataclass(eq=False)
class Group(Entity):
    metadata: SAMPR_GROUP_GENERAL_INFORMATION = field(repr=False, default=None)

    @staticmethod
    def delete(dce, domain_handle, uniq_id):
        resp = samr.hSamrOpenGroup(dce, domain_handle, groupId=uniq_id)
        group_handel = resp['GroupHandle']
        samr.hSamrDeleteGroup(dce, group_handel)

    @staticmethod
    def create(dce, domain_handle, name):
        resp = samr.hSamrCreateGroupInDomain(dce, domain_handle, name)
        return Group(name, resp['RelativeId'])

    @staticmethod
    def enumerate(dce, domain_handle):
        return samr.hSamrEnumerateGroupsInDomain(dce, domain_handle)

    @staticmethod
    def get_entity(dce, domain_handle, samr_obj):
        resp = samr.hSamrOpenGroup(dce, domain_handle, groupId=samr_obj['RelativeId'])
        info = samr.hSamrQueryInformationGroup(dce, resp['GroupHandle'])
        group = Group(samr_obj['Name'], samr_obj['RelativeId'], info['Buffer']['General'])
        samr.hSamrCloseHandle(dce, resp['GroupHandle'])
        return group


@dataclass(eq=False)
class Alias(Entity):
    metadata: SAMPR_ALIAS_GENERAL_INFORMATION = field(repr=False, default=None)

    @staticmethod
    def delete(dce, domain_handle, uniq_id):
        resp = samr.hSamrOpenAlias(dce, domain_handle, aliasId=uniq_id)
        group_handel = resp['AliasHandle']
        samr.hSamrDeleteAlias(dce, group_handel)

    @staticmethod
    def create(dce, domain_handle, name):
        resp = samr.hSamrCreateAliasInDomain(dce, domain_handle, name)
        return Group(name, resp['RelativeId'])

    @staticmethod
    def enumerate(dce, domain_handle):
        return samr.hSamrEnumerateAliasesInDomain(dce, domain_handle)

    @staticmethod
    def get_entity(dce, domain_handle, samr_obj):
        resp = samr.hSamrOpenAlias(dce, domain_handle, aliasId=samr_obj['RelativeId'])
        info = samr.hSamrQueryInformationAlias(dce, resp['AliasHandle'])
        alias = Alias(samr_obj['Name'], samr_obj['RelativeId'], info['Buffer']['General'])
        samr.hSamrCloseHandle(dce, resp['AliasHandle'])
        return alias

    # TODO: implement create and delete methods


@dataclass
class Target:
    domain: str
    username: str
    password: str
    remote_name: str
