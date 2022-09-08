## FortiADC Ansible Collection
***

The collection is the FortiADC Ansible Automation project. It includes the modules that are able to configure FortiADC OS features.

## Modules
The collection provides the following modules:


* `fadcos_admin` Configure FortiADC admin
* `fadcos_backup_config` Download FortiADC config file
* `fadcos_interfadce` Manage FortiADC network interface
* `fadcos_nat_pool` Configure NAT pool
* `fadcos_nat_pool_member` Configure NAT pool member 
* `fadcos_real_server` Configure real server 
* `fadcos_real_server_pool` Configure real server pool 
* `fadcos_real_server_pool_member` Configure real server pool member
* `fadcos_route_static` Configure static route
* `fadcos_system_control` Perform reboot/shutdown on FortiADC devices
* `fadcos_system_setting` Configure system setting
* `fadc_vdom` Manage FortiADC VDOM
* `fadcos_virtual_server_basic` Add a basic virtual server
* `fadcos_virtual_server` Configure virtual server
* `fadcos_application_profile` Configure an application profile
* `fadcos_cert_verify` Configure a certificate verification object
* `fadcos_client_ssl_profile` Configure a client SSL profile
* `fadcos_health_check` Configure an health check object
* `fadcos_local_cert_group` Configure a local certificate group
* `fadcos_real_server_ssl_profile` Configure a real server SSL profile

## Usage
This collection includes some playbooks for configuring ADC OS.
Here is a quick example:

Create the `hosts` inventory file
```
[fortiadc]
adc01 ansible_host=192.168.1.99 ansible_user="admin" ansible_password="password"

[fortiadc:vars]
ansible_network_os=fortinet.fortiadc.fadcos
ansible_httpapi_use_ssl=yes
ansible_httpapi_validate_certs=no
ansible_httpapi_port=443
```

Run the playbook:
```bash
ansible-playbook -i hosts fadcos_system_setting.yml
```

This operation will adjust system idle timeout.

For other playbooks, please make sure required settings are already done in ADC OS before running them.
