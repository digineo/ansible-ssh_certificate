# This is a action plugin for Ansible 2.0
# Put it in your action_plugins folder.

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import re
from datetime import datetime, timedelta
import subprocess
import tempfile

from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        ''' handler for file transfer operations '''
        if task_vars is None:
            task_vars = dict()

        result   = super(ActionModule, self).run(tmp, task_vars)

        ca_key   = self._task.args.get('ca_key')  # local path
        pub_key  = self._task.args.get('pub_key') # remote path
        hostname = self._task.args.get('hostname', task_vars['inventory_hostname'])
        validity = self._task.args.get('validity', "52w")

        if ca_key is None:
            result['failed'] = True
            result['msg'] = "ca_key is required"
            return result

        if not os.path.exists(ca_key):
            result['failed'] = True
            result['msg'] = "%s does not exist" % ca_key
            return result

        if pub_key is None:
            result['failed'] = True
            result['msg'] = "pub_key is required"
            return result

        if hostname is None or hostname == "":
            result['failed'] = True
            result['msg'] = "hostname is required"
            return result

        remote_pub  = pub_key
        remote_cert = pub_key.replace(".pub","-cert.pub")
        refresh     = True

        try:
            # Download existing certificate
            _, tmp_path = tempfile.mkstemp()
            self._connection.fetch_file(remote_cert, tmp_path)

            # Parse certificate
            output   = subprocess.check_output(["ssh-keygen", "-L", "-f", tmp_path])
            match    = re.search(r"Valid: from \S+ to (\S+)", output).group(1)
            validTo  = datetime.strptime(match, '%Y-%m-%dT%H:%M:%S')

            # Should it be replaced?
            refresh  = validTo < datetime.now() + timedelta(days=30)
        except AnsibleError:
            # Certificate does not exist (yet)
            pass
        finally:
            os.remove(tmp_path)

        if refresh:
            # Create a tempfile
            _, tmp_path = tempfile.mkstemp()
            tmp_cert    = tmp_path+"-cert.pub"

            # Download pubkey
            self._connection.fetch_file(remote_pub, tmp_path)

            # Create certificate
            subprocess.check_output(["ssh-keygen", "-s", ca_key, "-h", "-n", hostname, "-V", ("+%d" % validity), "-I", ("%s-key" % hostname), tmp_path])

            # Upload certificate
            res = self._connection.put_file(tmp_cert, remote_cert)

            result["changed"] = True

            os.remove(tmp_path)
            os.remove(tmp_cert)

        return result
