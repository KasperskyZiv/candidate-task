#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019

# Standard packages
import logging
from typing import List, Tuple

# External packages
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException, DCERPC
from impacket.dcerpc.v5.samr import USER_NORMAL_ACCOUNT
from impacket.dcerpc.v5.transport import DCERPCTransport, DCERPCTransportFactory
from impacket.nt_errors import STATUS_MORE_ENTRIES

# Project packages
from task.exceptions import ListUsersException, AddUserException
from task.objects import User

logger = logging.getLogger(__name__)


def dce_connection(func):
    """ Wrapper for SAMRConnection methods that needs a DCE/RPC session """

    def wrapper(self, remote_name, remote_host, *args, **kwargs):
        rpc_transport = self._set_rpc_connection(remote_name, remote_host)
        dce = self._dce_connect(rpc_transport)
        try:
            result = func(self, remote_name, remote_host, dce, *args, **kwargs)
        finally:
            # Close dce connection
            self._dce_disconnect(dce)
        return result

    return wrapper


class SAMRConnection:
    """ This class can be used to connect to a remote windows machine and using SAMR list/add users/groups"""

    def __init__(self, username: str = '', password: str = '', domain: str = '', hashes: str = None,
                 aes_key: str = None, do_kerberos: bool = False, kdc_host: str = None, port: int = 445):

        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aes_key = aes_key
        self.__do_kerberos = do_kerberos
        self.__kdc_host = kdc_host
        self.__port = port

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def _set_rpc_connection(self, remote_name, remote_host) -> DCERPCTransport:
        """
        Create an rpc session
        :param remote_name: remote name to use in rpc connection string
        :param remote_host: remote host to connect to
        :return: DCE/RPC Transport obj
        """
        logging.info(f'Retrieving endpoint list from {remote_name}')

        string_binding = r'ncacn_np:%s[\pipe\samr]' % remote_name
        # logging.debug('StringBinding %s' % string_binding)
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_dport(self.__port)
        rpc_transport.setRemoteHost(remote_host)

        if hasattr(rpc_transport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpc_transport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                          self.__nthash, self.__aes_key)
        rpc_transport.set_kerberos(self.__do_kerberos, self.__kdc_host)
        return rpc_transport

    @staticmethod
    def _dce_connect(rpc_transport: DCERPCTransport) -> DCERPC:
        """
        Create and bind an RPC session to remote host
        :param rpc_transport: RPC session settings
        :return: DCE/RPC session
        """
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        return dce

    @staticmethod
    def _dce_disconnect(dce: DCERPC):
        """ Stops DCE/RPC session """
        dce.disconnect()

    @staticmethod
    def __get_domain_handel(dce: DCERPC) -> Tuple[str, str]:
        """
        Request domain handel using DCERPC

        :param dce: DCE/RPC session
        :return: (domain name, domain handel)
        """
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp['Buffer']['Buffer']
        domain_names = [domain["Name"] for domain in domains]
        logger.info(f'Found domain(s): {", ".join(domain_names)}')

        # TODO: is it possible that the domain we need won't be the first one?
        domain_name = domain_names[0]
        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)

        resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=resp['DomainId'])
        domain_handle = resp['DomainHandle']
        return domain_name, domain_handle

    @staticmethod
    def __get_unix_time(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    @dce_connection
    def create_user(self, remote_name: str, remote_host: str,  dce: DCERPC, user_name: str, account_type: str = USER_NORMAL_ACCOUNT):
        """
        Create new user

        :param remote_name: remote name to use in rpc connection string
        :param remote_host: remote host to connect to (ip or name)
        :param dce: DCE/RPC session created using remote_name and remote_host
        :param user_name:  name of user to be created
        :param account_type: see USER_ACCOUNT Codes
        """

        domain_name, domain_handle = self.__get_domain_handel(dce)
        logger.info(f'Creating user "{user_name}" at domain "{domain_name}"')
        try:
            # Create user request
            resp = samr.hSamrCreateUser2InDomain(dce, domain_handle, user_name, accountType=account_type)
            logging.info("User {name} was created successfully with relative ID: {relative_id}".format(
                name=user_name, relative_id=resp['RelativeId']))
        except DCERPCException as e:
            raise AddUserException(e)

    @dce_connection
    def delete_user(self, remote_name: str, remote_host: str, dce: DCERPC, uid: str,
                    account_type: str = USER_NORMAL_ACCOUNT):
        """
        Delete user

        :param remote_name: remote name to use in rpc connection string
        :param remote_host: remote host to connect to (ip or name)
        :param dce: DCE/RPC session created using remote_name and remote_host
        :param uid:  user id to delete
        :param account_type: see USER_ACCOUNT Codes
        """

        domain_name, domain_handle = self.__get_domain_handel(dce)
        logger.info(f'Deleting user id "{uid}" at domain "{domain_name}"')
        try:
            # Delete user request
            resp = samr.hSamrOpenUser(dce, domain_handle, userId=uid)
            user_handel = resp['UserHandle']
            resp = samr.hSamrDeleteUser(dce, user_handel)
            logging.info(f"User id {uid} was deleted successfully")
        except DCERPCException as e:
            raise AddUserException(e)

    @dce_connection
    def list_all_users(self, remote_name: str, remote_host: str, dce: DCERPC) -> List[User]:
        """
        return a list of users and shares registered present at remote_name.

        :param remote_name: remote name to use in rpc connection string
        :param remote_host: remote host to connect to (ip or name)
        :param dce: DCE/RPC session created using remote_name and remote_host
        :return: list of users
        """
        entries = []
        users = []
        try:
            domain_name, domain_handle = self.__get_domain_handel(dce)

            logging.info('Looking up users in domain "%s"' % domain_name)
            status = STATUS_MORE_ENTRIES
            enumeration_context = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle,
                                                            enumerationContext=enumeration_context)
                except DCERPCException as e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise
                    resp = e.get_packet()

                for user in resp['Buffer']['Buffer']:
                    r = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                    # print("Found user: %s, uid = %d" % (user['Name'], user['RelativeId']))
                    info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],
                                                           samr.USER_INFORMATION_CLASS.UserAllInformation)
                    entry = (user['Name'], user['RelativeId'], info['Buffer']['All'])
                    entries.append(entry)
                    samr.hSamrCloseHandle(dce, r['UserHandle'])

                logging.info(f'Received {len(entries)} entries.')

                enumeration_context = resp['EnumerationContext']
                status = resp['ErrorCode']
                logger.debug(f"enumeration_context {enumeration_context}, status {status}")
                # create a User obj for each entry
                users = [User(*entry) for entry in entries]
        except Exception as e:
            raise ListUsersException(e)

        return users
