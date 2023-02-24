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
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fadcos_system_setting
description:
  - Configure system setting on FortiADC devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""


def get__sys_setting(module, connection):
    payload = {}
    code, response = connection.send_request(
        '/api/system_global', payload, 'GET')

    return code, response['payload']


def update_sys_setting(payload, connection):

    code, response = connection.send_request(
        '/api/system_global', payload, 'PUT')

    return code, response


def needs_update(module, sys_setting):
    res = False

    if module.params['idle_timeout'] and module.params['idle_timeout'] != sys_setting['admin-idle-timeout']:
        sys_setting['admin-idle-timeout'] = module.params['idle_timeout']
        res = True
    if module.params['config_sync'] and module.params['config_sync'] != sys_setting['config-sync-enable']:
        sys_setting['config-sync-enable'] = module.params['config_sync']
        res = True
    if module.params['intermediate_ca_group'] and module.params['intermediate_ca_group'] != sys_setting['default-intermediate-ca-group']:
        sys_setting['default-intermediate-ca-group'] = module.params['intermediate_ca_group']
        res = True
    if module.params['hostname'] and module.params['hostname'] != sys_setting['hostname']:
        sys_setting['hostname'] = module.params['hostname']
        res = True
    if module.params['http_port'] and module.params['http_port'] != sys_setting['http-port']:
        sys_setting['http-port'] = module.params['http_port']
        res = True
    if module.params['https_port'] and module.params['https_port'] != sys_setting['https-port']:
        sys_setting['https-port'] = module.params['https_port']
        res = True
    if module.params['https_server_cert'] and module.params['https_server_cert'] != sys_setting['https-server-cert']:
        sys_setting['https-server-cert'] = module.params['https_server_cert']
        res = True
    if module.params['ip_primary'] and module.params['ip_primary'] != sys_setting['ip_primary']:
        sys_setting['ip_primary'] = module.params['ip_primary']
        res = True
    if module.params['ip_second'] and module.params['ip_second'] != sys_setting['ip_second']:
        sys_setting['ip_second'] = module.params['ip_second']
        res = True
    if module.params['ssh_port'] and module.params['ssh_port'] != sys_setting['ssh-port']:
        sys_setting['ssh-port'] = module.params['ssh_port']
        res = True
    if module.params['sys_global_language'] and module.params['sys_global_language'] != sys_setting['sys-global-language']:
        sys_setting['sys-global-language'] = module.params['sys_global_language']
        res = True
    if module.params['telnet_port'] and module.params['telnet_port'] != sys_setting['telnet-port']:
        sys_setting['telnet-port'] = module.params['telnet_port']
        res = True
    if module.params['vdom'] and module.params['vdom'] != sys_setting['vdom-admin']:
        sys_setting['vdom-admin'] = module.params['vdom']
        res = True
    return res, sys_setting


def main():
    argument_spec = dict(
        idle_timeout=dict(type='str'),
        config_sync=dict(type='str'),
        intermediate_ca_group=dict(type='str'),
        hostname=dict(type='str'),
        http_port=dict(type='str'),
        https_port=dict(type='str'),
        https_server_cert=dict(type='str'),
        ip_primary=dict(type='str'),
        ip_second=dict(type='str'),
        ssh_port=dict(type='str'),
        sys_global_language=dict(type='str'),
        telnet_port=dict(type='str'),
        vdom=dict(type='str'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = []
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    connection = Connection(module._socket_path)
    result = {'changed': False}
    if not is_global_admin(connection):
        result['err_msg'] = 'The user is not global, can not access system setting config!'
        result['failed'] = True
    else:
        res, data = get__sys_setting(module, connection)
        update, update_data = needs_update(module, data)
        if update:
            code, response = update_sys_setting(update_data, connection)
            result['changed'] = True
            result['code'] = code
            result['res'] = 'updated'
        else:
            result['res'] = 'Do not update'
        result['update_data'] = data
    module.exit_json(**result)


if __name__ == '__main__':
    main()
