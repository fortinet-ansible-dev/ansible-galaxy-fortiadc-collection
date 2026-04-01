#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2022/05/02

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_to_str
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_need_update
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
				    'status': ['preview'],
				    'supported_by': 'network'}


DOCUMENTATION = """
module: fadcos_health_check_script
short_description: Configure health check script on FortiADC devices via RESTful APIs
description:
	Configure health check script on FortiADC devices via RESTful APIs
    User upload a local script file via API as to be the health check script
version_added: "v1.3.0"
author: josephchen@fortinet.com
options:
	action:
	    description: Type of action to perform on the object
    	required: Yes
    	type: String
    	default: N/A
	name:
	    description: Heath check script name.
    	required: Yes
    	type: String
    	default: N/A
	file:
	    description: filename containing the health check script.
    	required: Yes (for add and edit)
    	type: String
    	default: N/A
	vdom:
	    description: VDOM name if enabled.
    	required: Yes (if VDOM is enabled)
    	type: String
    	default: N/A
"""

EXAMPLES = """
- name:
  hosts: all
  vars:
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Add Health Checks
      fadcos_health_check_script:
		action: add
		name: mytest
		file: tst_script.sh
	
    - name: edit Health Checks
      fadcos_health_check_script:
		action: edit
		name: mytest
		file: tst_script2.sh
		
    - name: delete Health Checks
      fadcos_health_check_script:
		action: delete
		name: mytest
"""

RETURN = """
fadcos_health_check:
  description: The FortiADC health check object created or updated.
  returned: always
  type: string
"""

before = {}
after = {}

def add_hc_script(module, connection):
	after['added'] = module.params
	if 'file' in module.params.keys():
		f = open(module.params['file'], "r")
		content = f.read()
	payload = {
		'mkey': module.params['name'],
		'script': content,
		'scriptid': '1',
	}
		
	url = '/api/system_health_check_script'
	if is_vdom_enable(connection):
		vdom = module.params['vdom']
		url += '?vdom=' + vdom

	if module.check_mode:
		code = 0
		response = 'Check mode: changes detected.'
	else:
		code, response = connection.send_request(url, payload)

	return code, response

def get_hc_script(module, connection):
	name = module.params['name']
	payload = {}
	url = '/api/system_health_check_script'

	if name:
		url += '?mkey=' + name
	if is_vdom_enable(connection):
		vdom = module.params['vdom']
		if name:
			url += '&vdom=' + vdom
		else:
			url += '?vdom=' + vdom

	code, response = connection.send_request(url, payload, 'GET')
	return code, response

def delete_hc_script(module, connection):
	after['deleted'] = module.params
	name = module.params['name']
	payload = {}
	url = '/api/system_health_check_script?mkey=' + name

	if is_vdom_enable(connection):
		vdom = module.params['vdom']
		url += '&vdom=' + vdom

	if module.check_mode:
		code = 0
		response = 'Check mode: changes detected.' 
	else:
		code, response = connection.send_request(url, payload, 'DELETE')
	return code, response

def edit_hc_script(module, payload, connection):
	name = module.params['name']
	url = '/api/system_health_check_script?mkey=' + name

	if is_vdom_enable(connection):
		vdom = module.params['vdom']
		url += '&vdom=' + vdom

	if module.check_mode:
		code = 0
		response = 'Check mode: changes detected.' 
	else:
		code, response = connection.send_request(url, payload, 'PUT')
	return code, response

def update_hc_script(module, data):
	res = False

	if 'file' in module.params.keys():
		f = open(module.params['file'], "r")
		data['script'] = f.read()
		after['file'] = module.params['file']
		res = True

	return res, data

def param_check(module, connection):
	res = True
	action = module.params['action']
	err_msg = []

	if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
		err_msg.append('The health check name is required.')
		res = False
	if (action == 'add' or action == 'edit') and not module.params['file']:
		err_msg.append('The health check script filename is required.')
		res = False
	if is_vdom_enable(connection) and not module.params['vdom']:
		err_msg.append('The vdom is enabled in system setting, vdom must be set.')
		res = False
	elif is_vdom_enable(connection) and module.params['vdom'] and not is_user_in_vdom(connection, module.params['vdom']):
		err_msg.append('The user can not access the vdom ' + module.params['vdom'])
		res = False

	return res, err_msg

def main():
	argument_spec = dict(
		action=dict(type='str', required=True),
		name=dict(type='str'),
		file=dict(type='str'),
		vdom=dict(type='str'),
	)
	argument_spec.update(fadcos_argument_spec)

	required_if = [('name')]
	module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)
	connection = Connection(module._socket_path)

	action = module.params['action']
	result = {}
	param_pass, param_err = param_check(module, connection)
	if not param_pass:
		result['err_msg'] = param_err
		result['failed'] = True
		module.exit_json(**result)
	if action == 'add':
		code, response = add_hc_script(module, connection)
		result['res'] = response
		result['changed'] = True
	elif action == 'get':
		code, response = get_hc_script(module, connection)
		result['res'] = response
		result['ok'] = True
	elif action == 'edit':
		code, data = get_hc_script(module, connection)
		if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
			res, new_data = update_hc_script(module, data['payload'])
		else:
			res = False
			result['err_msg'] = 'Entry not found'
		if res:
			code, response = edit_hc_script(module, new_data, connection)
			result['res'] = response
			result['changed'] = True
	elif action == 'delete':
		code, data = get_hc_script(module, connection)
		if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
			code, response = delete_hc_script(module, connection)
			result['res'] = response
			result['changed'] = True
		else:
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
			if result['res']['payload'] == -15:
				result['failed'] = False
	if 'changed' in result.keys() and result['changed'] == True:
		result['diff'] = {
		    'before': before,
		    'after': after
		}
	else:
		if module.check_mode:
			result['res'] = 'Check mode: no changes detected.'

	module.exit_json(**result)
 


if __name__ == '__main__':
	main()
