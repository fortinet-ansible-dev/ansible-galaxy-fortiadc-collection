#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

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
module: fadcos_system_control
description:
  - Perform reboot/shutdown on FortiADC devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""


def reboot(connection):

    url = '/api/platform/reboot'
    payload = {}

    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def shutdown(connection):

    url = '/api/platform/shutdown'
    payload = {}

    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
    )
    argument_spec.update(fadcos_argument_spec)
    result = {}
    required_if = []
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    connection = Connection(module._socket_path)

    action = module.params['action']
    if action == "shutdown":
        code, response = shutdown(connection)
        result['res'] = response

    elif action == "reboot":
        code, response = reboot(connection)
        result['res'] = response

    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
