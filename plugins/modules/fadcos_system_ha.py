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
module: fadcos_system_ha
description:
  - Configure system setting on FortiADC devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/system_ha?vdom=&mkey=-1'

rep_dict = {
    'mgmt_interface': 'mgmt-interface',
    'local_node_id': 'local-node-id',
    'peer_address': 'peer-address',
    'group_name': 'group-name',
    'sync_l4_persistent': 'sync-l4-persistent',
    'monitor_enable': 'monitor-enable',
    'mgmt_ip_allowaccess': 'mgmt-ip-allowaccess',
    'config_priority': 'config-priority',
    'hb_lost_threshold': 'hb-lost-threshold',
    'node_list': 'node-list',
    'local_address': 'local-address',
    'mgmt_ip': 'mgmt-ip',
    'sync_l4_connection': 'sync-l4-connection',
    'failover_hold_time': 'failover-hold-time',
    'mgmt_status': 'mgmt-status',
    'sync_l7_persistent': 'sync-l7-persistent',
    'failover_threshold': 'failover-threshold',
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def edit_obj(payload, connection):
    url = obj_url
    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_obj(module, connection):
    payload = {}
    url = obj_url
    code, response = connection.send_request(url, payload, 'GET')

    return code, response['payload']


def combine_dict(src_dict, dst_dict):
    changed = False
    for key in dst_dict:
        if key in src_dict and src_dict[key] is not None and dst_dict[key] != src_dict[key]:
            dst_dict[key] = src_dict[key]
            changed = True

    return changed


def needs_update(module, data):
    res = False
    payload1 = {}
    payload1['data'] = module.params
    replace_key(payload1['data'], rep_dict)

    res = combine_dict(payload1['data'], data)
    data.pop('avaliable_ports')
    data.pop('monitor_list')
    data['_id'] = -1

    return res, payload1['data']


def main():
    argument_spec = dict(
        mgmt_interface=dict(type='str'),
        local_node_id=dict(type='str'),
        monitor_list_count=dict(type='int'),
        peer_address=dict(type='str'),
        group_name=dict(type='str'),
        sync_l4_persistent=dict(type='str'),
        monitor_enable=dict(type='str'),
        hbdev=dict(type='str'),
        mgmt_ip_allowaccess=dict(type='str'),
        config_priority=dict(type='str'),
        hb_lost_threshold=dict(type='str'),
        isSystemAdmin=dict(type='int'),
        override=dict(type='str'),
        groupid=dict(type='str'),
        node_list=dict(type='str'),
        local_address=dict(type='str'),
        isSystemWritable=dict(type='int'),
        mgmt_ip=dict(type='str'),
        sync_l4_connection=dict(type='str'),
        datadev=dict(type='str'),
        arp_num=dict(type='str'),
        failover_hold_time=dict(type='str'),
        interval=dict(type='str'),
        arp_interval=dict(type='str'),
        mode=dict(type='str'),
        mgmt_status=dict(type='str'),
        interface_list=dict(type='str'),
        sync_l7_persistent=dict(type='str'),
        hbtype=dict(type='str'),
        failover_threshold=dict(type='str'),
        priority=dict(type='str'),
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
        res, data = get_obj(module, connection)
        update, update_data = needs_update(module, data)
        if update:
            code, response = edit_obj(update_data, connection)
            result['changed'] = True
            result['code'] = code
            result['res'] = response
        else:
            result['res'] = 'Do not update'
        result['update_data'] = data
        result['send_data'] = update_data
    module.exit_json(**result)


if __name__ == '__main__':
    main()
