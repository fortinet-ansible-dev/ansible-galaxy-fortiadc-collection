from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

fadcos_argument_spec = dict()

import email.mime.multipart
import email.mime.text
from ansible.module_utils.common.collections import Mapping, is_sequence
from ansible.module_utils.six import string_types
from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text
import os

def list_to_str(data_list):
    data_str = ''
    if type(data_list) is list:
        for i in range(len(data_list)):
            data_str += ' ' + data_list[i]

    return data_str


def list_need_update(data_list, data_str):
    old_list = (data_str.lstrip().rstrip()).split(' ')
    if type(data_list) is not list:
        return False

    if len(data_list) != len(old_list):
        return True
    else:
        for i in range(len(data_list)):
            if data_list[i] not in old_list:
                return True

    return False


def is_global_admin(connection):
    payload = {}
    url = '/api/system_admin?mkey=' + str(connection.get_option('remote_user'))

    code, response = connection.send_request(url, payload, 'GET')

    user_data = response['payload']
    if type(user_data) is int and user_data < 0:
        return False

    if user_data['is-system-admin'] == 'yes':
        return True
    else:
        return False


def is_vdom_enable(connection):
    payload = {}
    code, response = connection.send_request(
        '/api/system_global', payload, 'GET')
    sys_setting = response['payload']

    if type(sys_setting) is int and sys_setting < 0:
        return True

    if 'vdom-admin' not in sys_setting.keys():
        return True
    elif sys_setting['vdom-admin'] == 'enable':
        return True
    else:
        return False


def is_user_in_vdom(connection, vdom):
    payload = {}
    url = '/api/system_admin?mkey=' + str(connection.get_option('remote_user')) + '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    user_data = response['payload']

    if type(user_data) is int and user_data < 0:
        return False

    if user_data['is-system-admin'] == 'yes':
        return True
    else:
        vdom_list = (user_data['vdom'].lstrip().rstrip()).split(' ')
        if vdom in vdom_list:
            return True
        else:
            return False


def get_err_msg(connection, err_id):
    payload = {}
    code, response = connection.send_request(
        '/api/platform/errMsg', payload, 'GET')
    if str(err_id) in response['payload']:
        err_msg = response['payload'][str(err_id)]
    else:
        err_msg = 'err code: ' + str(err_id)
    return err_msg

def prepare_multipart_base64(fields):
    if not isinstance(fields, Mapping):
        raise TypeError('Mapping is required, cannot be type %s' % fields.__class__.__name__)
    m = email.mime.multipart.MIMEMultipart('form-data')
    for field, value in sorted(fields.items()):
        if isinstance(value, string_types):
            main_type = 'text'
            sub_type = 'plain'
            content = value
            filename = None
        elif isinstance(value, Mapping):
            filename = value.get('filename')
            content = value.get('content')
            if not any((filename, content)):
                raise ValueError('at least one of filename or content must be provided')
            mime = value.get('mime_type')
            if not mime:
                try:
                    mime = mimetypes.guess_type(filename or '', strict=False)[0] or 'application/octet-stream'
                except Exception:
                    mime = 'application/octet-stream'
            main_type, sep, sub_type = mime.partition('/')
        else:
            raise TypeError('value must be a string, or mapping, cannot be type %s' % value.__class__.__name__)

        if not content and filename:
            f = open(to_bytes(filename, errors='surrogate_or_strict'), 'rb')
            part = email.mime.application.MIMEApplication(f.read())
        else:
            part = email.mime.nonmultipart.MIMENonMultipart(main_type, sub_type)
            part.set_payload(to_bytes(content))
        part.add_header('Content-Disposition', 'form-data')
        del part['MIME-Version']
        part.set_param('name', field, header='Content-Disposition')
        if filename:
            part.set_param('filename', to_native(os.path.basename(filename)), header='Content-Disposition')
        else:
            del part['Content-Type']
        m.attach(part)
    b_data = m.as_bytes(policy=email.policy.HTTP)
    del m
    headers, sep, b_content = b_data.partition(b'\r\n\r\n')
    del b_data
    parser = email.parser.BytesHeaderParser().parsebytes
    return (parser(headers)['content-type'], b_content)
