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


class TestSamrConnection:
    @classmethod
    def setup_class(cls):
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
        # delete test user
        cls.test_delete_user(cls)

    def test_list_all_users(self):
        users = self.samr_connection.list_all_users(self.target.remote_name, self.options.target_ip)
        assert [User(username='Administrator', uid=500),
                User(username='Guest', uid=501),
                User(username='krbtgt', uid=502),
                User(username='zivk', uid=1105)] == users, "listed users differ then expected"

    def test_add_user(self):
        self.samr_connection.create_user(self.target.remote_name, self.options.target_ip, "frank")
        users = self.samr_connection.list_all_users(self.target.remote_name, self.options.target_ip)
        assert [User(username='Administrator', uid=500),
                User(username='Guest', uid=501),
                User(username='krbtgt', uid=502),
                User(username='zivk', uid=1105),
                User(username='frank', uid=1108)]

    def test_delete_user(self):
        users = self.samr_connection.list_all_users(self.target.remote_name, self.options.target_ip)
        uid = None
        for user in users:
            if user.username == "frank":
                uid = user.uid
        if uid != None:
            self.samr_connection.delete_user(self.target.remote_name, self.options.target_ip, uid)
            users = self.samr_connection.list_all_users(self.target.remote_name, self.options.target_ip)
            assert [User(username='Administrator', uid=500),
                    User(username='Guest', uid=501),
                    User(username='krbtgt', uid=502),
                    User(username='zivk', uid=1105)] == users, "listed users differ then expected"
