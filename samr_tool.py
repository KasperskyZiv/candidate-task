#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019
"""
usage: samr_tool.py [-h] [-name name of user/group]
                    [-entity-id id of user/group] [-debug] [-dc-ip ip address]
                    [-target-ip ip address] [-port [destination port]]
                    [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                    command entity target

This script downloads the list of users for the target system.

positional arguments:
  command               command list/create/delete
  entity                The entity (group/user/alias) to list/create/delete
  target                [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help            show this help message and exit
  -name name of user/group
                        The name of user/group to create
  -entity-id id of user/group
                        The id of user/group to delete
  -debug                Turn DEBUG output ON

connection:
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target
                        parameter
  -target-ip ip address
                        IP Address of the target machine. If ommited it will
                        use whatever was specified as target. This is useful
                        when target is the NetBIOS name and you cannot resolve
                        it
  -port [destination port]
                        Destination port to connect to SMB Server

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
"""
# Standard packages
import sys
import logging
import argparse

# Project packages
from pprint import pprint

from objects import User, Group, Alias, Target
from smar_connection import SAMRConnection

logger = logging.getLogger(__name__)


name_to_entity = {"user": User,
                  "group": Group,
                  "alias": Alias}


def parse_args() -> object:
    """ Process command-line arguments. """
    parser = argparse.ArgumentParser(add_help=True, description="This script downloads the list of users for the "
                                                                "target system.")

    parser.add_argument('command', choices=['list', 'create', 'delete'], metavar="command",
                        help='command list/create/delete')
    parser.add_argument('entity', choices=['group', 'user', 'alias'], metavar="entity",
                        help='The entity (group/user/alias) to list/create/delete')
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-name', required='create' in sys.argv, action='store',
                        metavar='name of user/group', help='The name of user/group to create')
    parser.add_argument('-entity-id', required='delete' in sys.argv == 'create', action='store',
                        metavar='id of user/group', help='The id of user/group to delete')

    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in'
                            ' the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If ommited it will use whatever was specified as target.'
                            ' This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                            ' the ones specified in the command line')
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
    domain, username, password, remote_name = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    # In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    if domain is None:
        domain = ''

    if options.target_ip is None:
        options.target_ip = remote_name

    if options.aesKey is not None:
        options.k = True

    if (password == '' and username != '' and options.hashes is None and options.no_pass is False and
            options.aesKey is None):
        from getpass import getpass

        password = getpass("Password:")

    return options, Target(domain, username, password, remote_name)


if __name__ == '__main__':
    options, target = parse_args()
    LOG_FORMAT = "[%(levelname)s]: %(message)s"
    logging.basicConfig(level=logging.DEBUG if options.debug else logging.INFO,
                        format=LOG_FORMAT,
                        stream=sys.stdout)

    # Initialize SAMR instance
    samr_connection = SAMRConnection(target.username, target.password, target.domain,
                                     options.hashes,
                                     options.aesKey,
                                     options.k,
                                     options.dc_ip,
                                     int(options.port))
    try:
        if options.command == 'list':
            entities = samr_connection.list_all_entities(target.remote_name, options.target_ip,
                                                         name_to_entity[options.entity])
            pprint(entities)
        elif options.command == 'create':
            samr_connection.create_entity(target.remote_name, options.target_ip, name_to_entity[options.entity],
                                          options.name)
        elif options.command == 'delete':
            samr_connection.delete_entity(target.remote_name, options.target_ip, name_to_entity[options.entity],
                                          int(options.entity_id))
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(e, file=sys.stderr)
        logger.debug("Stack trace:", exc_info=True)
        exit(1)
