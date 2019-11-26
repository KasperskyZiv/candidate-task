#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019
import logging
import sys
from argparse import Namespace
from pprint import pprint

from impacket.dcerpc.v5 import samr

from task.exceptions import CreateEntityException
from task.objects import Target, User, Group, Alias
from task.smar_connection import SAMRConnection

logger = logging.getLogger(__name__)
LOG_FORMAT = "[%(levelname)s]: %(message)s"
logging.basicConfig(level=logging.DEBUG,
                    format=LOG_FORMAT,
                    stream=sys.stdout)

# Can be changed or loaded from file according to env
EXPECTED_USERS = [User(name='Administrator', uniq_id=500),
                  User(name='Guest', uniq_id=501),
                  User(name='krbtgt', uniq_id=502),
                  User(name='zivk', uniq_id=1105)]


class TestSamrConnection:
    test_user = None
    test_group = None
    samr_connection = None
    target = None
    options = None
    @classmethod
    def setup_class(cls):
        # Can be changed or loaded from file according to env
        # Also, possible to add other tests for working with hashes, kerberos etc..
        cls.options = Namespace(aesKey=None, dc_ip='192.168.1.150', debug=True, hashes=None, k=False, no_pass=False,
                                port='445',
                                target='kaspersky.local/zivk:1q2w#E$R@192.168.1.150', target_ip='192.168.1.150')
        cls.target = Target(domain='kaspersky.local', username='zivk', password='1q2w#E$R', remote_name='192.168.1.150')
        cls.samr_connection = SAMRConnection(cls.target.username, cls.target.password, cls.target.domain,
                                             cls.options.hashes,
                                             cls.options.aesKey,
                                             cls.options.k,
                                             cls.options.dc_ip,
                                             int(cls.options.port))


    def test_list_all_users(self):
        users = self.samr_connection.list_all_entities(self.target.remote_name, self.options.target_ip, User)
        assert EXPECTED_USERS == users, "listed users differ then expected"

    def test_add_user(self):
        self.test_user = self.samr_connection.create_entity(self.target.remote_name, self.options.target_ip, User, "frank")
        users = self.samr_connection.list_all_entities(self.target.remote_name, self.options.target_ip, User)
        assert all(user in users for user in EXPECTED_USERS) and any(user.name == "frank" for user in users)
        self.test_del_user()

    def test_del_user(self):
        users = self.samr_connection.list_all_entities(self.target.remote_name, self.options.target_ip, User)
        uid = None
        for user in users:
            if user.name == "frank":
                uid = user.uniq_id
                break
        if uid != None:  # not sure if uid 0 is possible
            self.samr_connection.delete_entity(self.target.remote_name, self.options.target_ip, User, uid)
            self.test_list_all_users()

    def test_list_groups(self):
        groups = self.samr_connection.list_all_entities(self.target.remote_name, self.options.target_ip, Group)
        # pprint(groups)
        assert 13 == (len(groups)), "number of groups is not as expected"

    def test_list_aliases(self):
        aliases = self.samr_connection.list_all_entities(self.target.remote_name, self.options.target_ip, Alias)
        assert 33 == (len(aliases)), "number of groups is not as expected"

    def test_add_group(self):
        try:
            self.test_group = self.samr_connection.create_entity(self.target.remote_name, self.options.target_ip, Group, "Avengers")
        except CreateEntityException as e:
            if "The specified group already exists" in str(e.args[0]):
                # Group already exists
                pass
        groups = self.samr_connection.list_all_entities(self.target.remote_name, self.options.target_ip, Group)
        assert 14 == (len(groups)), "number of groups is not as expected"
        self.test_del_group()

    def test_del_group(self):
        group = self.samr_connection.list_all_entities(self.target.remote_name, self.options.target_ip, Group)
        gid = None
        for group in group:
            if group.name == "Avengers":
                gid = group.uniq_id
                break
        if gid != None:  # not sure if uid 0 is possible
            self.samr_connection.delete_entity(self.target.remote_name, self.options.target_ip, Group, gid)
            self.test_list_groups()

