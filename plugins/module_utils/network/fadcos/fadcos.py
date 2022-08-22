from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

fadcos_argument_spec = dict()


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
    if user_data['is-system-admin'] == 'yes':
        return True
    else:
        return False


def is_vdom_enable(connection):
    payload = {}
    code, response = connection.send_request(
        '/api/system_global', payload, 'GET')
    sys_setting = response['payload']
    if 'vdom-admin' not in sys_setting.keys():
        return True
    elif sys_setting['vdom-admin'] == 'enable':
        return True
    else:
        return False


def is_user_in_vdom(connection, vdom):
    payload = {}
    url = '/api/system_admin?mkey=' + str(connection.get_option('remote_user'))
    code, response = connection.send_request(url, payload, 'GET')

    user_data = response['payload']
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
