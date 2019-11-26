#!/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019

# Standard packages
import sys
import logging
import argparse

# External packages
# from impacket import version


# Project packages
from objects import Target

logger = logging.getLogger(__name__)


def parse_args() -> object:
    """ Process command-line arguments. """
    parser = argparse.ArgumentParser(add_help=True, description="This script downloads the list of users for the "
                                                                "target system.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
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

    # # Explicitly changing the stdout encoding format
    # if sys.stdout.encoding is None:
    #     # Output is redirected to a file
    #     sys.stdout = codecs.getwriter('utf8')(sys.stdout)


