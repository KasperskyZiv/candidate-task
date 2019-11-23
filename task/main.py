#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019

# Standard packages
import sys
import logging
import argparse
import codecs
from pprint import pprint
from typing import List

# External packages
from impacket import version
from impacket.dcerpc.v5.transport import DCERPCTransport
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException

# Project packages
from task.exceptions import ListUsersException
from task.objects import User
from task.old import LOG_FORMAT

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
        entries = []



        rpctransport = self.__set_rpc_connection(remote_name, remote_host)

        try:
            entries = self.__fetch_user_list(rpctransport)
        except Exception as e:
            logging.critical(str(e))
            logging.debug('StackTrace: ', exc_info=True)

        users = [User(*entry) for entry in entries]

        if entries:
            num = len(entries)
            if 1 == num:
                logging.info('Received one entry.')
            else:
                logging.info('Received %d entries.' % num)
        else:
            logging.info('No entries received.')

        return users

    def __set_rpc_connection(self, remote_name, remote_host) -> DCERPCTransport:
        """
        Create an rpc session
        :param remote_name: remote name to use in rpc connection string
        :param remote_host: remote host to connect to
        :return: DCE/RPC Transport obj
        """
        logging.info(f'Retrieving endpoint list from {remoteName}')

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
    def __dce_connect(rpc_transport):
        """
        Create and bind an RPC session to remote host
        :param rpc_transport: (DCERPCTransportFactory) RPC session settings
        :return: DCE/RPC session
        """
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        return dce

    @staticmethod
    def __dce_disconnect(dce):
        dce.disconnect()

    def __fetch_user_list(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        entries = []

        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        try:
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']
            domain_names = [domain["Name"] for domain in domains]
            logger.info(f'Found domain(s): {", ".join(domain_names)}')

            for domain_name in domain_names:
                logging.info('Looking up users in domain "%s"' % domain_name)

                resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domain_name)

                resp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=resp['DomainId'])
                domainHandle = resp['DomainHandle']

                status = STATUS_MORE_ENTRIES
                enumerationContext = 0
                while status == STATUS_MORE_ENTRIES:
                    try:
                        resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                    except DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()

                    for user in resp['Buffer']['Buffer']:
                        r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                        # print("Found user: %s, uid = %d" % (user['Name'], user['RelativeId']))
                        info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],
                                                               samr.USER_INFORMATION_CLASS.UserAllInformation)
                        entry = (user['Name'], user['RelativeId'], info['Buffer']['All'])
                        entries.append(entry)
                        samr.hSamrCloseHandle(dce, r['UserHandle'])

                    enumerationContext = resp['EnumerationContext']
                    status = resp['ErrorCode']

        except ListUsersException as e:
            logging.critical("Error listing users: %s" % e)
            logging.debug('StackTrace: ', exc_info=True)

        dce.disconnect()

        return entries


# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logging.basicConfig(level=logging.DEBUG,
                        format=LOG_FORMAT,
                        stream=sys.stdout)

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="This script downloads the list of users for the "
                                                                "target system.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. If '
                                                                                'ommited it will use whatever was specified as target. This is useful when target is the NetBIOS '
                                                                                'name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re

    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    # In case the password contains '@'
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if domain is None:
        domain = ''

    if options.target_ip is None:
        options.target_ip = remoteName

    if options.aesKey is not None:
        options.k = True

    if (password == '' and username != '' and options.hashes is None and options.no_pass is False and
            options.aesKey is None):
        from getpass import getpass

        password = getpass("Password:")

    dumper = SAMRConnection(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip,
                            int(options.port))
    pprint(dumper.list_all_users(remoteName, options.target_ip))
