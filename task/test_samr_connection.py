#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019
import logging
import sys
from argparse import Namespace
from pprint import pprint

from task.objects import Target, User
from task.samr_connection import SAMRConnection

logger = logging.getLogger(__name__)
LOG_FORMAT = "[%(levelname)s]: %(message)s"
logging.basicConfig(level=logging.DEBUG,
                    format=LOG_FORMAT,
                    stream=sys.stdout)

# Can be changed or loaded from file according to env
EXPECTED_USERS = [User(user_name='Administrator', uid=500),
                  User(user_name='Guest', uid=501),
                  User(user_name='krbtgt', uid=502),
                  User(user_name='zivk', uid=1105)]


class TestSamrConnection:
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
        users = self.samr_connection.list_all_users(self.target.remote_name, self.options.target_ip)
        assert EXPECTED_USERS == users, "listed users differ then expected"

    def test_add_user(self):
        self.samr_connection.create_user(self.target.remote_name, self.options.target_ip, "frank")
        users = self.samr_connection.list_all_users(self.target.remote_name, self.options.target_ip)
        assert all(user in users for user in EXPECTED_USERS) and any(user.user_name == "frank" for user in users)

    def test_del_user(self):
        users = self.samr_connection.list_all_users(self.target.remote_name, self.options.target_ip)
        uid = None
        for user in users:
            if user.user_name == "frank":
                uid = user.uid
        if uid != None:  # not sure if uid 0 is possible
            self.samr_connection.delete_user(self.target.remote_name, self.options.target_ip, uid)
            self.test_list_all_users()

    def test_list_groups(self):
        groups = self.samr_connection.list_all_groups(self.target.remote_name, self.options.target_ip)
        assert 33 == (len(groups)), "number of groups is not as expected"

    def test_add_group(self):
        pass

    def test_del_group(self):
        pass