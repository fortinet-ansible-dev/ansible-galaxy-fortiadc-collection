#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_to_str
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_need_update
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_global_admin
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fadcos_admin
short_description: Configure FortiADC admin by RESTful API
description:
  - Manage admin on FortiADC devices including creating, updating, removing admin objects,
    All operations are performed RESTful API.
version_added: "2.8"
author: "Ansible by Red Hat (@rcarrillocruz)"
options:
  name:
    description:
      - Name of the admin.
    type: str
  trused_hosts:
    description:
      - trused hosts.
    required: True
    type: str
    default: 0.0.0.0/0 ::/0
  global_admin:
    description:
      - global admin.
    type: str
    default: yes
  profile:
    description:
      - profile
    type: str
  vdom:
    description:
      - Destionation object of the access rule.
    type: str
    default: root
  password:
    description:
      - password
    required: True
    type: str
"""

EXAMPLES = """
- name: Create admin
  fadcos_admin:
    name: newuser
    password: newpwd

"""

RETURN = """
fadcos_admin:
  description: The FortiADC admin object created or updated.
  returned: always.
  type: string
"""


def add_admin(module, connection):
    name = module.params['name']
    trused_hosts = module.params['trused_hosts']
    global_admin = module.params['global_admin']
    profile = module.params['profile']
    vdom = list_to_str(module.params['vdom'])
    wildcard = module.params['wildcard']
    auth_stratgey = module.params['auth_stratgey']
    ldap_server = module.params['ldap_server']
    radius_server = module.params['radius_server']
    password = module.params['password']
    admin_type = module.params['admin_type']
    auth_strategy = module.params['auth_strategy']

    payload = {'mkey': name,
               'is-system-admin': global_admin,
               'trusted-host': trused_hosts,
               'profile': profile,
               'vdom': vdom,
               'wildcard': wildcard,
               'auth_stratgey': auth_stratgey,
               'passwd': password,
               'auth_ldap_server_id': ldap_server,
               'auth_radius_server_id': radius_server,
               'admin-type': admin_type,
               'auth_strategy': auth_strategy,
               }

    url = '/api/system_admin'
    if not is_global_admin(connection):
        url += '?vdom=' + module.params['vdom'][0]

    code, response = connection.send_request(url, payload)

    return code, response


def edit_admin(module, payload, connection):
    name = module.params['name']
    url = '/api/system_admin?mkey=' + name

    if not is_global_admin(connection):
        url += '&vdom=' + module.params['vdom'][0]

    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_admin(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/system_admin'

    if name:
        url += '?mkey=' + name
    if not is_global_admin(connection):
        if name:
            url += '&'
        else:
            url += '?'
        url += 'vdom=' + module.params['vdom'][0]

    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_admin(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/system_admin?mkey=' + name

    if not is_global_admin(connection):
        url += '&vdom=' + module.params['vdom'][0]

    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

    if module.params['trused_hosts'] and module.params['trused_hosts'] != data['trusted-host']:
        data['trusted-host'] = module.params['trused_hosts']
        res = True
    if module.params['global_admin'] and module.params['global_admin'] != data['is-system-admin']:
        data['is-system-admin'] = module.params['global_admin']
        res = True
    if module.params['profile'] and module.params['profile'] != data['profile']:
        data['profile'] = module.params['profile']
        res = True
    if module.params['vdom'] and list_need_update(module.params['vdom'], data['vdom']):
        data['vdom'] = list_to_str(module.params['vdom'])
        res = True
    if module.params['wildcard'] and module.params['wildcard'] != data['wildcard']:
        data['wildcard'] = module.params['wildcard']
        res = True
    if module.params['password']:
        data['passwd'] = module.params['password']
        res = True
    if module.params['auth_stratgey'] and module.params['auth_stratgey'] != data['auth_stratgey']:
        data['auth_stratgey'] = module.params['auth_stratgey']
        res = True
    if module.params['ldap_server'] and module.params['ldap_server'] != data['auth_ldap_server_id']:
        data['auth_ldap_server_id'] = module.params['ldap_server']
        res = True
    if module.params['radius_server'] and module.params['radius_server'] != data['auth_radius_server_id']:
        data['auth_radius_server_id'] = module.params['radius_server']
        res = True
    if module.params['oldpassword'] and module.params['password'] and module.params['oldpassword'] != module.params['password']:
        data['oldpwd'] = module.params['oldpassword']
        res = True
    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    if module.params['auth_stratgey'] == 'local' and module.params['password'] is None:
        err_msg = 'password need to set'
        res = False
    if module.params['auth_stratgey'] == 'radius' and module.params['radius_server'] is None:
        err_msg = 'radius_server need to set'
        res = False
    if module.params['auth_stratgey'] == 'ldap' and module.params['ldap_server'] is None:
        err_msg = 'ldap_server need to set'
        res = False
    if module.params['global_admin'] and module.params['global_admin'] == "False":
        module.params['global_admin'] = "no"
    elif module.params['global_admin'] and module.params['global_admin'] == "True":
        module.params['global_admin'] = "yes"

    if not module.params['vdom'] and not is_global_admin(connection):
        err_msg = 'user is not global admin then vdom need to set'
        res = False

    if module.params['vdom'] and not is_global_admin(connection):
        if len(module.params['vdom']) > 1:
            err_msg = 'user is not global admin can not access multi vdom for new admin'
            res = False
        elif not is_user_in_vdom(connection, module.params['vdom'][0]):
            err_msg = 'user is not global admin can not access the vdom ' + \
                module.params['vdom'][0] + ' for new admin'
            res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        trused_hosts=dict(type='str', default='0.0.0.0/0 ::/0'),
        global_admin=dict(type='str', default='no'),
        profile=dict(type='str', default='super_admin_prof'),
        vdom=dict(type='list'),
        auth_stratgey=dict(type='str'),
        oldpassword=dict(type='str'),
        password=dict(type='str'),
        radius_server=dict(type='str'),
        ldap_server=dict(type='str'),
        wildcard=dict(type='str', default='disable'),
        admin_type=dict(type='str', default='normal'),
        auth_strategy=dict(type='str', default='local'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)
    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'add':
        code, response = add_admin(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_admin(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_admin(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_admin(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_admin(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_admin(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
