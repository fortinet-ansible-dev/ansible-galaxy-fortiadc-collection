#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_to_str
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_need_update
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_global_admin
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fadcos_real_server_pool_member
description:
  - Configure real server pool member on FortiADC devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""


def add_rs_pool_member(module, connection):
    pkey = module.params['pool_name']
    member_id = module.params['member_id']
    port = module.params['port']
    rs = module.params['rs']
    status = module.params['status']
    recover = module.params['recover']
    rs_profile_inherit = module.params['rs_profile_inherit']
    rs_profile = module.params['rs_profile']
    warmrate = module.params['warmrate']
    weight = module.params['weight']
    warmup = module.params['warmup']
    backup = module.params['backup']
    connlimit = module.params['connlimit']
    connection_ratelimit = module.params['connection_ratelimit']
    cookie = module.params['cookie']
    health_check_inherit = module.params['health_check_inherit']
    health_check = module.params['health_check']
    health_check_list = list_to_str(module.params['health_check_list'])
    health_check_relationship = module.params['health_check_relationship']
    mysql_group_id = module.params['mysql_group_id']
    mysql_read_only = module.params['mysql_read_only']
    vdom = module.params['vdom']

    payload = {'mkey': member_id,
               'status': status,
               'real_server_id': rs,
               'port': port,
               'recover': recover,
               'rs_profile_inherit': rs_profile_inherit,
               'weight': weight,
               'warmup': warmup,
               'warmrate': warmrate,
               'connlimit': connlimit,
               'connection-rate-limit': connection_ratelimit,
               'cookie': cookie,
               'health_check_inherit': health_check_inherit,
               'm_health_check': health_check,
               'm_health_check_list': health_check_list,
               'm_health_check_relationship': health_check_relationship,
               'mysql_group_id': mysql_group_id,
               'mysql_read_only': mysql_read_only,
               'backup': backup,
               'rs_profile': rs_profile,

               }

    url = '/api/load_balance_pool_child_pool_member?pkey=' + pkey
    if is_vdom_enable(connection):
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)

    return code, response


def edit_rs_pool_member(module, payload, connection):
    member_id = module.params['member_id']
    pkey = module.params['pool_name']
    vdom = module.params['vdom']
    url = '/api/load_balance_pool_child_pool_member?pkey=' + pkey + '&mkey=' + member_id
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_rs_pool_member(module, connection):
    member_id = module.params['member_id']
    pkey = module.params['pool_name']
    vdom = module.params['vdom']
    payload = {}
    url = '/api/load_balance_pool_child_pool_member?pkey=' + pkey
    if member_id:
        url += '&mkey=' + member_id
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_rs_pool_member(module, connection):
    member_id = module.params['member_id']
    pkey = module.params['pool_name']
    vdom = module.params['vdom']
    payload = {}
    url = '/api/load_balance_pool_child_pool_member?pkey=' + pkey + '&mkey=' + member_id
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

    if module.params['status'] and module.params['status'] != data['status']:
        data['status'] = module.params['status']
        res = True
    if module.params['rs'] and module.params['rs'] != data['real_server_id']:
        data['real_server_id'] = module.params['rs']
        res = True
    if module.params['port'] and module.params['port'] != data['port']:
        data['port'] = module.params['port']
        res = True
    if module.params['recover'] and module.params['recover'] != data['recover']:
        data['recover'] = module.params['recover']
        res = True
    if module.params['rs_profile_inherit'] and module.params['rs_profile_inherit'] != data['rs_profile_inherit']:
        data['rs_profile_inherit'] = module.params['rs_profile_inherit']
        res = True
    if module.params['weight'] and module.params['weight'] != data['weight']:
        data['weight'] = module.params['weight']
        res = True
    if module.params['warmup'] and module.params['warmup'] != data['warmup']:
        data['warmup'] = module.params['warmup']
        res = True
    if module.params['warmrate'] and module.params['warmrate'] != data['warmrate']:
        data['warmrate'] = module.params['warmrate']
        res = True
    if module.params['connlimit'] and module.params['connlimit'] != data['connlimit']:
        data['connlimit'] = module.params['connlimit']
        res = True
    if module.params['connection_ratelimit'] and module.params['connection_ratelimit'] != data['connection-rate-limit']:
        data['connection-rate-limit'] = module.params['connection_ratelimit']
        res = True
    if module.params['cookie'] and module.params['cookie'] != data['cookie']:
        data['cookie'] = module.params['cookie']
        res = True
    if module.params['health_check_inherit'] and module.params['health_check_inherit'] != data['health_check_inherit']:
        data['health_check_inherit'] = module.params['health_check_inherit']
        res = True
    if module.params['health_check'] and module.params['health_check'] != data['m_health_check']:
        data['m_health_check'] = module.params['health_check']
        res = True
    if list_need_update(module.params['health_check_list'], data['m_health_check_list']):
        data['m_health_check_list'] = list_to_str(
            module.params['health_check_list'])
        res = True
    if module.params['health_check_relationship'] and module.params['health_check_relationship'] != data['m_health_check_relationship']:
        data['m_health_check_relationship'] = module.params['health_check_relationship']
        res = True
    if module.params['mysql_group_id'] and module.params['mysql_group_id'] != data['mysql_group_id']:
        data['mysql_group_id'] = module.params['mysql_group_id']
        res = True
    if module.params['mysql_read_only'] and module.params['mysql_read_only'] != data['mysql_read_only']:
        data['mysql_read_only'] = module.params['mysql_read_only']
        res = True
    if module.params['backup'] and module.params['backup'] != data['backup']:
        data['backup'] = module.params['backup']
        res = True
    if module.params['rs_profile'] and module.params['rs_profile'] != data['rs_profile']:
        data['rs_profile'] = module.params['rs_profile']
        res = True

    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['member_id']:
        err_msg.append('The member_id need to set.')
        res = False
    if action == 'add' and not module.params['rs']:
        err_msg.append('The rs need to set.')
        res = False
    if is_vdom_enable(connection) and not module.params['vdom']:
        err_msg.append(
            'The vdom is enable in system setting, vdom must be set.')
        res = False
    elif is_vdom_enable(connection) and module.params['vdom'] and not is_user_in_vdom(connection, module.params['vdom']):
        err_msg.append('The user can not accsee the vdom ' +
                       module.params['vdom'])
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        pool_name=dict(type='str', required=True),
        member_id=dict(type='str'),
        rs=dict(type='str'),
        status=dict(type='str', default='enable'),
        port=dict(type='str', default='80'),
        recover=dict(type='str', default='0'),
        rs_profile_inherit=dict(type='str', default='enable'),
        rs_profile=dict(type='str', default='NONE'),
        weight=dict(type='str', default='1'),
        warmup=dict(type='str', default='0'),
        warmrate=dict(type='str', default='100'),
        backup=dict(type='str', default='disable'),
        connlimit=dict(type='str', default='0'),
        connection_ratelimit=dict(type='str', default='0'),
        cookie=dict(type='str', default=''),
        health_check_inherit=dict(type='str', default='enable'),
        health_check=dict(type='str', default='disable'),
        health_check_list=dict(type='list'),
        health_check_relationship=dict(type='str', default='AND'),
        mysql_group_id=dict(type='str', default='0'),
        mysql_read_only=dict(type='str', default='disable'),
        vdom=dict(type='str'),
    )
    argument_spec.update(fadcos_argument_spec)
    required_if = []
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    connection = Connection(module._socket_path)

    action = module.params['action']
    result = {}
    param_pass, param_err = param_check(module, connection)
    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'add':
        code, response = add_rs_pool_member(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_rs_pool_member(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_rs_pool_member(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_rs_pool_member(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_rs_pool_member(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
            code, response = delete_rs_pool_member(module, connection)
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
