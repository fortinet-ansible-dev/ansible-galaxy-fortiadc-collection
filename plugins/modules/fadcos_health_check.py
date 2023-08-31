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
module: fadcos_health_check
description:
	Configure health checks on FortiADC devices via RESTful APIs
supported types:	ICMP, TCP Echo, TCP, HTTP, HTTPS, DNS, RADIUS, SMTP,
				POP3, IMAP4, RADIUS Accounting, FTP, TCP Half Open Conn,
				TCP SSL, SNMP, SSH, L2 Detection, UDP, SIP, SIP TCP, RTSP,
				MySQL, Diameter, Script, Oracle, LDAP, MSSQL
version_added: "v1.0.0"
author: asri@fortinet.com
options:
	action:
	    description: Type of action to perform on the object
    	required: Yes
    	type: String
    	default: N/A
	addr_type:
	    description: Type of address (IPv4/IPv6)
    	required: No
    	type: String
    	default: ipv4
	agent_type:
	    description: SNMP agent type
    	required: No
    	type: String
    	default: UCD
	acct_appid:
	    description: Specify the type Unsigned32 accounting application ID used to advertise support of the accounting portion of an application.
    	required: No
    	type: String
    	default: 0
	auth_appid: 
	    description: Specify the type Unsigned32 authentication application ID used to advertise support of the authentication and authorization portion of an application.
    	required: No
    	type: String
    	default: 0
	allow_ssl_version:
	    description: Allowed SSL versions
    	required: No
    	type: String
    	default: sslv3 tlsv1.0 tlsv1.1 tlsv1.2 
	attribute:
	    description: Attributes for the LDAP health check object.
    	required: No
    	type: String
    	default: 
	basedn:
	    description: The distinguished name where a LDAP server will search from.
    	required: No
    	type: String
    	default:
	binddn:
	    description: The distinguished name used to bind to a LDAP server.
    	required: No
    	type: String
    	default:
	column:
	    description: The column in which the send string (command) takes effect
    	required: No
    	type: String
    	default:
	community:
	    description: Must match the SNMP community string set on the backend server. If this does not match, all SNMP health checks fail.
    	required: No
    	type: String
    	default:
	compare_type:
	    description: SNMP compare type
    	required: No
    	type: String
    	default: less
	connect_type:
	    description: Oracle connect type
    	required: No
    	type: String
    	default: service_name
	cpu:
	    description: Maximum normal CPU usage. If overburdened, the health check fails.
    	required: No
    	type: String
    	default: 96
	cpu_weight:
	    description: CPU Weight
    	required: No
    	type: String
    	default: 100
	database:
	    description: Database
    	required: No
    	type: String
    	default:
	dest_addr:
	    description: IP address to send health check traffic.
    	required: No
    	type: String
    	default: 0.0.0.0
	dest_addr6:
	    description: IP address to send health check traffic.
    	required: No
    	type: String
    	default: ::
	dest_addr_type:
	    description: Destination address IP type.
    	required: No
    	type: String
    	default: ipv4
	disk:
	    description: Maximum normal disk usage. If the disk is too full, the health check fails.
    	required: No
    	type: String
    	default: 96
	disk_weight:
	    description: Disk Weight
    	required: No
    	type: String
    	default: 100
	domain_name:
	    description: The FQDN, such as www.example.com, to use in the DNS A/AAAA record health check.
    	required: No
    	type: String
    	default:
	down_retry:
	    description: Attempts to retry the health check to see if an up server has become unavailable.
    	required: No
    	type: String
    	default:
	file_name:
	    description: Specify a file that exists on the backend server. Path is relative to the initial login path. If the file does not exist or is not accessible, the health check fails.
    	required: No
    	type: String
    	default: welcome.txt
	folder_name:
	    description: Select an email mailbox to use in the health check. If the mailbox does not exist or is not accessible, the health check fails. The default is INBOX.
    	required: No
    	type: String
    	default: INBOX
	host_ip6_addr:
	    description: Specify the type IPv6 address used to inform a Diameter peer of the sender's IP address when the destination address type is IPv6. The default is blank, meaning that it is the address of the FortiADC's outgoing interface.
    	required: No
    	type: String
    	default: ::
	host_ip_addr:
	    description: Specify the type IPv4 address used to inform a Diameter peer of the sender's IP address when the destination address type is IPv4. The default is blank, meaning that it is the address of the FortiADC's outgoing interface.
    	required: No
    	type: String
    	default: 0.0.0.0
	hostname:
	    description: For HTTP or HTTPS health checks, you can specify the hostname (FQDN) instead of the destination IP address. This is useful in VM environments where multiple applications have the same IP address.
    	required: No
    	type: String
    	default:
	http_extra_string:
	    description: The non-empty additional string should end with '\r\n'.
    	required: No
    	type: String
    	default:
	host_addr:
	    description: IP address that matches the FQDN, indicating a successful health check.
    	required: No
    	type: String
    	default: 0.0.0.0
	host_addr6:
	    description: IP address that matches the FQDN, indicating a successful health check.
    	required: No
    	type: String
    	default: ::
	http_connect: 
	    description: If the real server pool members are HTTP proxy servers, specify an HTTP CONNECT option.
    	required: No
    	type: String
    	default: no_connect
	http_version:
	    description: Specify the HTTP version
    	required: No
    	type: String
    	default: http_1.1
	interval:
	    description: Seconds between each health check. Should be more than the timeout to prevent overlapping health checks. 
    	required: No
    	type: String
    	default: 5
	filter:
	    description: Criteria to use in selecting results.
    	required: No
    	type: String
    	default:
	local_cert:
	    description: Local SSL Health Check Client certificate.
    	required: No
    	type: String
    	default: Factory
	match_type:
	    description: Match String/Match Status/Match All (match both string and status)
    	required: No
    	type: String
    	default: match_string
	mem:
	    description: Maximum normal RAM usage. If overburdened, the health check fails.
    	required: No
    	type: String
    	default: 96
	mem_weight:
	    description: Memory weight
    	required: No
    	type: String
    	default: 100
	method_type:
	    description: HTTP method for the test traffic.
    	required: No
    	type: String
    	default: http_head
	mssql_row:
	    description: The row in which the send string (command) takes effect
    	required: No
    	type: String
    	default:
	mssql_column:
	    description: The column in which the send string (command) takes effect
    	required: No
    	type: String
    	default:
	mssql_receive_string:
	    description: A string expected in return when the request is successful.
    	required: No
    	type: String
    	default:
	mssql_send_string: 
	    description: The request string.
    	required: No
    	type: String
    	default:
	mysql_server_type:
	    description: MySQL server type (primary/secondary)
    	required: No
    	type: String
    	default: primary
	name:
	    description: Heath check name.
    	required: Yes
    	type: String
    	default: N/A
	nas_ip:
	    description: NAS IP address RADIUS attribute (if the RADIUS server requires this attribute to make a connection).
    	required: No
    	type: String
    	default:
	oracle_receive_string: 
	    description: The string we accept in order to receive.
    	required: No
    	type: String 
    	default:
	oracle_send_string:
	    description: Send a string (command) to the OracleDb server.
    	required: No
    	type: String
    	default:
	origin_host:
	    description: Specify the FortiADC appliance that originates the Diameter message. The value is in FQDN format and used to uniquely identify a Diameter node for duplicate connection and routing loop detection.
    	required: No
    	type: String
    	default:
	origin_realm:
	    description: Specify the realm of the FortiADC appliance that originates the Diameter message. The value is in FQDN format.
    	required: No
    	type: String
    	default:
	passive:
	    description: Select this option if the backend server uses passive FTP.
    	required: No
    	type: String
    	default: enable
	password:
	    description: Specify the password, if applicable.
    	required: No
    	type: String
    	default:
	pwd_type:
	    description: RADIUS password type (User/CHAP)
    	required: No
    	type: String
    	default: user-password
	port:
	    description: Specify the port number. Valid values range from 0 to 65535.
    	required: No
    	type: String
    	default: 0
	product_name:
	    description: Specify the type UTF8String product name which contains the vendor assigned name for the product.
    	required: No
    	type: String
    	default: FortiADC
	radius_reject:
	    description: RADIUS reject (enable/disable)
    	required: No
    	type: String
    	default: disable
	receive_string:
	    description: A string expected in return when the HTTP GET request is successful.
    	required: No
    	type: String
    	default: receive-string
	rtsp_method_type:
	    description: RTSP Options/RTSP Describe
    	required: No
    	type: String
    	default: options
	rtsp_describe_url:
	    description: Specify the RTSP describe URL
    	required: No
    	type: String
    	default:
	row:
	    description: The row in which the send string (command) takes effect
    	required: No
    	type: String
    	default:
	remote_username: 
	    description: Remote server username.
    	required: No
    	type: String
    	default:
	remote_password:
	    description: Remote server password, if applicable.
    	required: No
    	type: String
    	default:
	remote_host:
	    description: If you use HTTP CONNECT to test proxy servers, specify the remote server IP address.
    	required: No
    	type: String
    	default:
	remote_port:
	    description: If you use HTTP CONNECT to test proxy servers, specify the remote server port.
    	required: No
    	type: String
    	default: 0
	script:
	    description: Specify the script which we create or which we have pre-defined
    	required: No
    	type: String
    	default: CURL_HTTP_CODE
	secret_key:
	    description: The secret set on the backend server.
    	required: No
    	type: String
    	default:
	send_string:
	    description: The request URL, such as /contact.php.
    	required: No
    	type: String
    	default: /
	sip_request_type:
	    description: Specify the SIP request type to be used for health checks: SIP Options/SIP Register
    	required: No
    	type: String
    	default: register
	ssl_ciphers: 
	    description: List of SSL ciphers
    	required: No
    	type: List
    	default:
	status_code:
	    description: The health check sends an HTTP request to the server. Specify the HTTP status code in the server reply that indicates a successful test. Typically, you use status code 200 (OK). Other status codes indicate errors..
    	required: No
    	type: String
    	default: 200
	timeout:
	    description: Seconds to wait for a reply before assuming that the health check has failed. The default is 5.
    	required: No
    	type: String
    	default: 3
	hc_type:
	    description: Health Check Type.
    	required: Yes
    	type: String
    	default: N/A
	up_retry:
	    description: Attempts to retry the health check to see if a down server has become available.
    	required: No
    	type: String
    	default: 1
	username:
	    description: Username of an account on the backend server.
    	required: No
    	type: String
    	default:
	vendor_id:
	    description: Specify the type Unsigned32 vendor ID which contains the IANA "SMI Network Management Private Enterprise Codes" value assigned to the vendor of a Diameter application.
    	required: No
    	type: String
    	default: 12356
	version:
	    description: SNMP v1 or v2c.
    	required: No
    	type: String
    	default: v1
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
    - name: Manage Health Checks
      fadcos_health_check:
        action: add
        name: test_hc_tcp
        port: 4
        username: uname
        password: pass
        file_name: aaa.txt
        dest_addr_type: ipv4
        dest_addr: 1.2.3.4
        up_retry: 1
        down_retry: 3
        interval: 5
        timeout: 3
        hc_type: tcp
        vdom: root
"""

RETURN = """
fadcos_health_check:
  description: The FortiADC health check object created or updated.
  returned: always
  type: string
"""

def add_hc(module, connection):

	payload = {
		'addr_type': module.params['addr_type'],
		'agent-type': module.params['agent_type'],
		'allow-ssl-verison': module.params['allow_ssl_version'],
		'acct-appid': module.params['acct_appid'],
		'auth-appid': module.params['auth_appid'],
		'attribute': module.params['attribute'],
		'baseDN': module.params['basedn'],
		'bindDN': module.params['binddn'],
		'column': module.params['column'],
		'community': module.params['community'],
		'compare-type': module.params['compare_type'],
		'connect-type': module.params['connect_type'],
		'cpu': module.params['cpu'],
		'cpu_weight': module.params['cpu_weight'],
		'database': module.params['database'],
		'dest_addr': module.params['dest_addr'],
		'dest_addr6': module.params['dest_addr6'],
		'dest_addr_type': module.params['dest_addr_type'],
		'disk': module.params['disk'],
		'disk-weight': module.params['disk_weight'],
		'domain_name': module.params['domain_name'],
		'down_retry': module.params['down_retry'],
		'file_name': module.params['file_name'],
		'filter': module.params['filter'],
		'folder_name': module.params['folder_name'],
		'host-ip6-addr': module.params['host_ip6_addr'],
		'host-ip-addr': module.params['host_ip_addr'],
		'hostname': module.params['hostname'],
		'http_extra_string': module.params['http_extra_string'],
		'host_addr': module.params['host_addr'],
		'host_addr6': module.params['host_addr6'],
		'http_connect': module.params['http_connect'],
		'http_version': module.params['http_version'],
		'interval': module.params['interval'],
		'local_cert': module.params['local_cert'],
		'match_type': module.params['match_type'],
		'mem': module.params['mem'],
		'mem-weight': module.params['mem_weight'],
		'method_type': module.params['method_type'],
		'mkey': module.params['name'],
		'mssql-column': module.params['mssql_column'],
		'mssql-row': module.params['mssql_row'],
		'mssql-receive-string': module.params['mssql_receive_string'],
		'mssql-send-string': module.params['mssql_send_string'],
		'mysql-server-type': module.params['mysql_server_type'],
		'nas-ip': module.params['nas_ip'],
		'oracle-receive-string': module.params['oracle_receive_string'],
		'oracle-send-string': module.params['oracle_send_string'],
		'origin-host': module.params['origin_host'],
		'origin-realm': module.params['origin_realm'],
		'passive': module.params['passive'],
		'password': module.params['password'],
		'pwd_type': module.params['pwd_type'],
		'port': module.params['port'],
		'product-name': module.params['product_name'],
		'radius-reject': module.params['radius_reject'],
		'reveive_string': module.params['receive_string'],
		'row': module.params['row'],
		'remote-username': module.params['remote_username'],
		'remote-password': module.params['remote_password'],
		'remote_host': module.params['remote_host'],
		'remote_port': module.params['remote_port'],
		'rtsp-method-type': module.params['rtsp_method_type'],
		'rtsp-describe-url': module.params['rtsp_describe_url'],
		'script': module.params['script'],
		'secret_key': module.params['secret_key'],
		'send_string': module.params['send_string'],
		'sip_request_type': module.params['sip_request_type'],
		'ssl-ciphers': list_to_str(module.params['ssl_ciphers']),
		'status_code': module.params['status_code'],
		'timeout': module.params['timeout'],
		'type': module.params['hc_type'],
		'up_retry': module.params['up_retry'],
		'username': module.params['username'],
		'vendor-id': module.params['vendor_id'],
		'version': module.params['version'],
		}

	url = '/api/system_health_check'
	if is_vdom_enable(connection):
		vdom = module.params['vdom']
		url += '?vdom=' + vdom
	
	code, response = connection.send_request(url, payload)

	return code, response

def get_hc(module, connection):
	name = module.params['name']
	payload = {}
	url = '/api/system_health_check'

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

def delete_hc(module, connection):
	name = module.params['name']
	payload = {}
	url = '/api/system_health_check?mkey=' + name

	if is_vdom_enable(connection):
		vdom = module.params['vdom']
		url += '&vdom=' + vdom

	code, response = connection.send_request(url, payload, 'DELETE')
	return code, response

def edit_hc(module, payload, connection):
	name = module.params['name']
	url = '/api/system_health_check?mkey=' + name

	if is_vdom_enable(connection):
		vdom = module.params['vdom']
		url += '&vdom=' + vdom

	code, response = connection.send_request(url, payload, 'PUT')
	return code, response

def update_hc(module, data):
	res = False

	parameter_map = {
		'agent_type': 'agent-type',
		'allow_ssl_verison': 'allow-ssl-version',
		'acct_appid': 'acct-appid',
		'auth_appid': 'auth-appid',
		'baseDN': 'basedn',
		'bindDN': 'binddn',
		'compare_type': 'compare-type',
		'connect_type': 'connect-type',
		'file_name': 'file',
		'folder_name': 'folder',
		'host_ip6_addr': 'host-ip6-addr',
		'host_ip_addr': 'host-ip-addr',
		'mem_weight': 'mem-weight',
		'mssql_column': 'mssql-column',
		'mssql_row': 'mssql-row',
		'mssql_receive_string': 'mssql-receive-string',
		'mssql_send_string': 'mssql-send-string',
		'mysql_server_type': 'mysql-server-type',
		'nas_ip': 'nas-ip',
		'oracle_receive_string': 'oracle-receive-string',
		'oracle_send_string': 'oracle-send-string',
		'origin_host': 'origin-host',
		'origin_realm': 'origin-realm',
		'product_name': 'product-name',
		'radius_reject': 'radius-reject',
		'remote_username': 'remote-username',
		'remote_password': 'remote-password',
		'rtsp_method_type': 'rtsp-method-type',
		'rtsp_describe_url': 'rtsp-describe-url',
		'ssl_ciphers': 'ssl-ciphers',
		'hc_type': 'type',
		'vendor_id': 'vendor-id',
		}

	for param in module.params:
		key = parameter_map.get(param)
		if key == None:
			key = param
		if key in data:
			if key == 'ssl-ciphers':
				if list_need_update(module.params[param], data[key]):
					data[key] = list_to_str(module.params[param])
					res = True
			else:
				if module.params[param] != data[key]:
					data[key] = module.params[param]
					res = True

	return res, data

def param_check(module, connection):
	res = True
	action = module.params['action']
	err_msg = []

	if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
	    err_msg.append('The health check name is required.')
	    res = False
	if action == 'add' and not module.params['hc_type']:
	    err_msg.append('The health check type is required.')
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
		addr_type=dict(type='str', default='ipv4'),
		agent_type=dict(type='str', default='UCD'),
		acct_appid=dict(type='str', default='0'),
		auth_appid=dict(type='str', default='0'),
		allow_ssl_version=dict(type='str', default='sslv3 tlsv1.0 tlsv1.1 tlsv1.2'),
		attribute=dict(type='str', default=''),
		basedn=dict(type='str', default=''),
		binddn=dict(type='str', default=''),
		column=dict(type='str', default=''),
		community=dict(type='str', default=''),
		compare_type=dict(type='str', default='less'),
		connect_type=dict(type='str', default='service_name'),
		cpu=dict(type='str', default='96'),
		cpu_weight=dict(type='str', default='100'),
		database=dict(type='str', default=''),
		dest_addr=dict(type='str', default='0.0.0.0'),
		dest_addr6=dict(type='str', default='::'),
		dest_addr_type=dict(type='str', default='ipv4'),
		disk=dict(type='str', default='96'),
		disk_weight=dict(type='str', default='100'),
		domain_name=dict(type='str', default=''),
		down_retry=dict(type='str', default='3'),
		file_name=dict(type='str', default='welcome.txt'),
		folder_name=dict(type='str', default='INBOX'),
		host_ip6_addr=dict(type='str', default='::'),
		host_ip_addr=dict(type='str', default='0.0.0.0'),
		hostname=dict(type='str', default=''),
		http_extra_string=dict(type='str', default=''),
		host_addr=dict(type='str', default='0.0.0.0'),
		host_addr6=dict(type='str', default='::'),
		http_connect=dict(type='str', default='no_connect'),
		http_version=dict(type='str', default='http_1.1'),
		interval=dict(type='str', default='5'),
		filter=dict(type='str', default=''),
		local_cert=dict(type='str', default='Factory'),
		match_type=dict(type='str', default='match_string'),
		mem=dict(type='str', default='96'),
		mem_weight=dict(type='str', default='100'),
		method_type=dict(type='str', default='http_head'),
		mssql_row=dict(type='str', default=''),
		mssql_column=dict(type='str', default=''),
		mssql_receive_string=dict(type='str', default=''),
		mssql_send_string=dict(type='str', default=''),
		mysql_server_type=dict(type='str', default='primary'),
		name=dict(type='str'),
		nas_ip=dict(type='str', default=''),
		oracle_receive_string=dict(type='str', default=''),
		oracle_send_string=dict(type='str', default=''),
		origin_host=dict(type='str', default=''),
		origin_realm=dict(type='str', default=''),
		passive=dict(type='str', default='enable'),
		password=dict(type='str', default=''),
		pwd_type=dict(type='str', default='user-password'),
		port=dict(type='str', default='0'),
		product_name=dict(type='str', default='FortiADC'),
		radius_reject=dict(type='str', default='disable'),
		receive_string=dict(type='str', default='receive-string'),
		rtsp_method_type=dict(type='str', default='options'),
		rtsp_describe_url=dict(type='str', default=''),
		row=dict(type='str', default=''),
		remote_username=dict(type='str', default=''),
		remote_password=dict(type='str', default=''),
		remote_host=dict(type='str', default=''),
		remote_port=dict(type='str', default='0'),
		script=dict(type='str', default='CURL_HTTP_CODE'),
		secret_key=dict(type='str', default=''),
		send_string=dict(type='str', default='/'),
		sip_request_type=dict(type='str', default='register'),
		ssl_ciphers=dict(type='list'),
		status_code=dict(type='str', default='200'),
		timeout=dict(type='str', default='3'),
		hc_type=dict(type='str'),
		up_retry=dict(type='str', default='1'),
		username=dict(type='str', default=''),
		vendor_id=dict(type='str', default='12356'),
		version=dict(type='str', default='v1'),
		vdom=dict(type='str'),
	)
	argument_spec.update(fadcos_argument_spec)

	required_if = [('name')]
	module = AnsibleModule(argument_spec=argument_spec, required_if=required_if)
	connection = Connection(module._socket_path)

	action = module.params['action']
	result = {}
	param_pass, param_err = param_check(module, connection)
	if not param_pass:
		result['err_msg'] = param_err
		result['failed'] = True
	elif action == 'add':
		code, response = add_hc(module, connection)
		result['res'] = response
		result['changed'] = True
	elif action == 'get':
		code, response = get_hc(module, connection)
		result['res'] = response
		result['ok'] = True
	elif action == 'edit':
		code, data = get_hc(module, connection)
		if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
			res, new_data = update_hc(module, data['payload'])
		else:
			result['failed'] = True
			res = False
			result['err_msg'] = 'Entry not found'
		if res:
			code, response = edit_hc(module, new_data, connection)
			result['res'] = response
			result['changed'] = True
	elif action == 'delete':
		code, data = get_hc(module, connection)
		if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
			code, response = delete_hc(module, connection)
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
