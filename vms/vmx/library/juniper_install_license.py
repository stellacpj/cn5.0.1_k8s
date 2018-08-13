#!/usr/bin/env python
import paramiko
from os.path import isfile
from jnpr.junos import Device
from jnpr.junos.utils.start_shell import StartShell
from jnpr.junos.utils.sw import SW
from jnpr.junos.exception import ConnectError, RpcError

class MyStartShell(StartShell):
    def open(self):
        junos = self._nc
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=junos.hostname,
                       port=junos._port,
                       username=junos._auth_user,
                       password=junos._auth_password,
                       )
        chan = client.invoke_shell()
        self._client = client
        self._chan = chan
        got = self.wait_for(r'(%|>|#)')
        if got[-1].endswith('> '):
            self.send('start shell')
            self.wait_for('(%|#)\s')

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', required=True),
            port=dict(type='int', default=830),
            user=dict(type='str', default='root'),
            password=dict(type='str', default=None, no_log=True),
            license=dict(type='str', required=True),
            shutdown=dict(type='bool', default=False)
        ),
        supports_check_mode=True)

    args = module.params

    if not isfile(args['license']):
        module.fail_json(msg="license not found: {0}".format(args['license']))
        return

    dev = Device(args['host'], user=args['user'], password=args['password'], port=args['port']).open()

    with MyStartShell(dev) as sh:
        license = open(args['license']).read().splitlines()
        for line in license:
            sh.run('echo %s >> /var/tmp/license.lic' % line)
        sh.run('cli -c "request system license add /var/tmp/license.lic"')

    if args['shutdown']:
        try:
            SW(dev).poweroff()
        except RpcError:
            pass

    module.exit_json(failed=False, changed=True)

from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
