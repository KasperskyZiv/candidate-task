# !/usr/bin/env python3
# Created by Ziv Kaspersky at 11/23/2019

# Standard packages
import logging
from typing import List, Tuple, Dict, Type

# External packages
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException, DCERPC
from impacket.dcerpc.v5.transport import DCERPCTransport
from impacket.nt_errors import STATUS_MORE_ENTRIES

# Project packages
from exceptions import DeleteEntityException, CreateEntityException, ListEntitiesException
from objects import Entity

logger = logging.getLogger(__name__)


def dce_connection(func):
    """ Wrapper for SAMRConnection methods that needs a DCE/RPC session """

    def wrapper(self, remote_name, remote_host, *args, **kwargs):
        rpc_transport = self._set_rpc_connection(remote_name, remote_host)
        dce = self._dce_connect(rpc_transport)
        try:
            result = func(self, dce, *args, **kwargs)
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

    def list_all_entities(self, remote_name: str, remote_host: str, entity_type: Type[Entity]) -> List[Entity]:
        """
        return a list of entities (users, groups..) present at remote_name.

        :param remote_name: remote name to use in rpc connection string
        :param remote_host: remote host to connect to (ip or name)
        :param entity_type: class of entity to list
        :return: list of entities
        """
        return self.__list_all_entities(remote_name, remote_host, entity_type)

    def delete_entity(self, remote_name: str, remote_host: str, entity_type: Type[Entity], uniq_id: int):
        """
        Delete an entity (user, group..) present at remote_name.

        :param uniq_id: Id of entity to delete
        :param remote_name: remote name to use in rpc connection string
        :param remote_host: remote host to connect to (ip or name)
        :param entity_type: class of entity to delete
        """
        self.__delete_entity(remote_name, remote_host, entity_type, uniq_id)

    def create_entity(self, remote_name: str, remote_host: str, entity_type: Type[Entity], name: str):
        """
        Creates an entity (user, group..) present at remote_name.

        :param name: Name of entity to create
        :param remote_name: remote name to use in rpc connection string
        :param remote_host: remote host to connect to (ip or name)
        :param entity_type: class of entity to delete
        :return entity created
        """
        return self.__create_entity(remote_name, remote_host, entity_type, name)

    def _set_rpc_connection(self, remote_name, remote_host) -> DCERPCTransport:
        """
        Create an rpc session
        :param remote_name: remote name to use in rpc connection string
        :param remote_host: remote host to connect to
        :return: DCE/RPC Transport obj
        """
        logging.info(f'Retrieving endpoint list from {remote_name}')

        string_binding = r'ncacn_np:%s[\pipe\samr]' % remote_name
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
    def __get_domain_handels(dce: DCERPC) -> Dict[str, str]:
        """
        Request domain handel using DCERPC

        :param dce: DCE/RPC session
        :return: mapping of domain name -> domain handel
        """
        domains = {}
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        raw_domains = resp['Buffer']['Buffer']
        domain_names = [domain["Name"] for domain in raw_domains]
        logger.info(f'Found domain(s): {", ".join(domain_names)}')
        for domain_name in domain_names:
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=resp['DomainId'])
            domain_handle = resp['DomainHandle']
            domains[domain_name] = domain_handle

        return domains

    def __get_domain_handel(self, dce: DCERPC) -> Tuple[str, str]:
        """ Returns the first non builtin domain in domain list with domain handel """
        # I know it's a bit messy but i'm not sure if there would be more then one, non Builtin (whatever that
        # means), domain return from hSamrEnumerateDomainsInSamServer, and i hate to remove some functionality that
        # might be in use later
        domains = self.__get_domain_handels(dce)
        domains.pop("Builtin")
        return domains.popitem()

    @dce_connection
    def __list_all_entities(self, dce: DCERPC, entity: Entity) -> List[Entity]:
        entities = []
        try:
            # iterating over all domains
            for domain_name, domain_handle in self.__get_domain_handels(dce).items():
                if entity.filter_out_domain(domain_name):
                    # filtering domains according to entity logic
                    break
                logging.info(f'Looking up {entity.__name__} in domain "{domain_name}"')
                status = STATUS_MORE_ENTRIES
                while status == STATUS_MORE_ENTRIES:
                    try:
                        resp = entity.enumerate(dce, domain_handle)
                    except DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()

                    for _entity in resp['Buffer']['Buffer']:
                        _entity = entity.get_entity(dce, domain_handle, _entity)
                        entities.append(_entity)

                    logging.info(f'Received {len(entities)} entries.')

                    enumeration_context = resp['EnumerationContext']
                    status = resp['ErrorCode']
                    logger.debug(f"enumeration_context {enumeration_context}, status {status}")
        except Exception as e:
            raise ListEntitiesException(e)

        return entities

    @dce_connection
    def __delete_entity(self, dce: DCERPC, entity: Entity, uniq_id: int):
        domain_name, domain_handle = self.__get_domain_handel(dce)
        logger.info(f'Deleting {entity.__name__} with id ({uniq_id}) from domain "{domain_name}"')
        try:
            entity.delete(dce, domain_handle, uniq_id)
        except Exception as e:
            raise DeleteEntityException(e)
        logging.info(f'{entity.__name__} id ("){uniq_id}) was deleted successfully')

    @dce_connection
    def __create_entity(self, dce: DCERPC, entity: Entity, name: str):
        domain_name, domain_handle = self.__get_domain_handel(dce)
        logger.info(f'Creating {entity.__name__} named "{name}" at domain "{domain_name}"')
        try:
            entity = entity.create(dce, domain_handle, name)
        except Exception as e:
            raise CreateEntityException(e)
        logging.info(f'{entity.__class__.__name__} named "{name}" was created successfully with relative ID: {entity.uniq_id}')
        return entity
