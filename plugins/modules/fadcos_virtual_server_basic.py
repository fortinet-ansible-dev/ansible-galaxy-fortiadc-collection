#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_global_admin
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fadcos_virtual_server_basic
description:
  - Add a basic virtual server via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""


def add_basic_vs(module, connection):
    name = module.params['name']
    application = module.params['application']
    address = module.params['address']
    interface = module.params['interface']
    pool = module.params['pool']
    port = module.params['port']
    vdom = module.params['vdom']

    payload = {'mkey': name,
               'application': application,
               'address': address,
               'interface': interface,
               'pool': pool,
               'port': port
               }

    url = '/api/load_balance_virtual_server/vs_advanced_edit'
    if is_vdom_enable(connection):
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)
    response['post'] = payload

    return code, response


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        application=dict(type='str', required=True),
        address=dict(type='str', required=True),
        interface=dict(type='str', required=True),
        pool=dict(type='str', required=True),
        port=dict(type='str', required=True),
        ssl=dict(type='str', default='disable'),
        ssl_profile=dict(type='str'),
        vdom=dict(type='str'),
    )
    argument_spec.update(fadcos_argument_spec)
    result = {}
    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    connection = Connection(module._socket_path)
    if is_vdom_enable(connection) and not module.params['vdom']:
        result['err_msg'] = 'The vdom is enable, please set vdom'
        result['failed'] = True
    elif is_vdom_enable(connection) and module.params['vdom'] and not is_user_in_vdom(connection, module.params['vdom']):
        result['err_msg'] = 'The user can not accsee the vdom ' + \
            module.params['vdom']
        result['failed'] = True
    else:
        code, response = add_basic_vs(module, connection)
        result = {'code': code}
        result['res'] = response
        result['changed'] = True

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
