#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/15

from __future__ import (absolute_import, division, print_function)
import os
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fadcos_backup_config
short_description: Download FortiADC config file by RESTful API
description:
  - Download FortiADC config file by RESTful API.
version_added: "2.8"
author: ""
options:
  path:
    description:
      - The config file save path
    required: True
    type: str
  password:
    description:
      - The config file unzip password
    type: str
"""

EXAMPLES = """
- name: Create admin
  fadcos_backup_config:
    path: /tmp/fortiadc/
    password: pwd

"""

RETURN = """
fadcos_backup_config:
  description: The config file name.
  returned: always.
  type: string
"""


'''/api/system_global/back_config_disk'''


def save_config_adc(module, connection):

    if module.params['name']:
        name = module.params['name']
    else:
        name = 'Ansiblebackup'

    payload = {
        'fullConfig': True,
        'name': name,
    }

    url = '/api/system_global/back_config_disk'
    code, response = connection.send_request(url, payload)

    return code, response


def get_config_disk(connection):
    payload = {}
    url = '/api/system_global/show_config_disk'

    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def backup_config(module, connection):
    path = module.params['path']
    pwd = ''
    if not module.params['password']:
        pwd = module.params['password']

    url = '/api/downloader/config?entire=enable&type=' + \
        module.params['configtype'] + '&password=' + pwd

    if module.params['configtype'] == 'adc':
        name = module.params['name']
        url += '&name=' + name

    filename = connection.download_file(url, path)

    return filename


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        configtype=dict(type='str', default='local'),
        path=dict(type='str'),
        password=dict(type='str'),
        name=dict(type='str', default='Ansiblebackup'),
    )
    argument_spec.update(fadcos_argument_spec)
    result = {}
    required_if = []
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    connection = Connection(module._socket_path)

    action = module.params['action']
    if action == 'download':
        if os.path.exists(module.params['path']):
            filename = backup_config(module, connection)
            result['config_file'] = filename
        else:
            err_msg = 'The path ' + module.params['path'] + ' is not exists'
            result['err'] = err_msg
            result['failed'] = True
    elif action == 'save':
        code, response = save_config_adc(module, connection)
        result['res'] = response
    elif action == 'list':
        code, response = get_config_disk(connection)
        result['res'] = response
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
