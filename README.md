Ansible module for SSH certificates
===================================

This action module for Ansible 2.x creates and renews SSH certificates.

## Installation

Copy the `ssh_certificate.py` to a `action_plugins` folder and add it to your `action_plugins` search path.

To extend your search path, set in `ansible.cfg`:

```
action_plugins = /usr/share/ansible_plugins/action_plugins:./action_plugins
```

## Usage

### Example playbook

```yaml
---
- hosts: all
  tasks:
  - name: Create certificate
    ssh_certificate:
      ca_key: /path/to/local/ca_key
      pub_key: /etc/ssh/ssh_host_ed25519_key.pub

  - name: Enable certificate
    lineinfile:
      dest: /etc/ssh/sshd_config
      regexp: "^HostCertificate "
      line: "HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub"
    notify:
    - reload ssh

  handlers:
  - name: reload ssh
    service: name=ssh state=reloaded

```

### Options

* `ca_key` (required) path to the local CA key file.
* `pub_key` (required) path to the remote destination for the certificate file.
* `hostname` hostname to be included in the certificate. Defaults to the variable `inventory_hostname`.
* `validity` validity period. Defaults to `52w` for 52 weeks.

### Rewewal

Certificates will be replaced if the validity period ends in less than 30 days.
