#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019

# Standard packages
import logging
from typing import List, Tuple

# External packages
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException, DCERPC
from impacket.dcerpc.v5.samr import SAMPR_USER_ALL_INFORMATION
from impacket.dcerpc.v5.transport import DCERPCTransport, DCERPCTransportFactory
from impacket.nt_errors import STATUS_MORE_ENTRIES

# Project packages
from task.exceptions import ListUsersException
from task.objects import User

logger = logging.getLogger(__name__)


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

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def list_all_users(self, remote_name: str, remote_host: str) -> List[User]:
        """return a list of users and shares registered present at
        remoteName. remoteName is a valid host name or IP address.
        """
        # Create an DCE/RPC session

        rpctransport = self.__set_rpc_connection(remote_name, remote_host)

        try:
            entries = self.__fetch_user_list(rpctransport)
        except Exception as e:
            logging.critical(str(e))
            logging.debug('StackTrace: ', exc_info=True)
            return []

        # create a User obj for each entry
        users = [User(*entry) for entry in entries]

        logging.info(f'Received {len(entries)} entries.')

        return users

    def __set_rpc_connection(self, remote_name, remote_host) -> DCERPCTransport:
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
    def __dce_connect(rpc_transport: DCERPCTransport) -> DCERPC:
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
    def __dce_disconnect(dce: DCERPC):
        """ Stops current dce session"""
        dce.disconnect()

    def __fetch_user_list(self, rpc_transport: DCERPCTransport) -> List[Tuple[str, int, SAMPR_USER_ALL_INFORMATION]]:
        """ Retrieves user list using SAMR"""
        entries = []
        dce = self.__dce_connect(rpc_transport)

        try:
            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp['Buffer']['Buffer']
            domain_names = [domain["Name"] for domain in domains]
            logger.info(f'Found domain(s): {", ".join(domain_names)}')

            for domain_name in domain_names:
                logging.info('Looking up users in domain "%s"' % domain_name)

                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)

                resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=resp['DomainId'])
                domain_handle = resp['DomainHandle']

                status = STATUS_MORE_ENTRIES
                enumeration_context = 0
                while status == STATUS_MORE_ENTRIES:
                    try:
                        resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle, enumerationContext=enumeration_context)
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

                    enumeration_context = resp['EnumerationContext']
                    status = resp['ErrorCode']

        except ListUsersException as e:
            logging.critical("Error listing users: %s" % e)
            logging.debug('StackTrace: ', exc_info=True)

        self.__dce_disconnect(dce)
        return entries
