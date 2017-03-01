########
# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

#
# IPTables plugin implementation
#
from cloudify.decorators import operation
from cloudify import ctx
from cloudify.exceptions import NonRecoverableError
from fabric.api import env, run, sudo
from StringIO import StringIO


def _validate_firewall_rule(rule):
    ctx.logger.info("RULE:{}".format(str(rule)))
    if 'protocol' not in rule:
        rule['protocol'] = 'tcp'
    elif rule['protocol'] != 'tcp' and rule['protocol'] != 'udp':
        raise NonRecoverableError("unknown protocol: {}".format(
            rule['protocol']))
    if 'direction' not in rule:
        rule['direction'] = 'ingress'
    elif rule['direction'] != 'ingress' and rule['direction'] != 'egress':
        raise NonRecoverableError("direction must be ingress or egress")
    if 'interface' not in rule:
        rule['interface'] = 'eth0'
    if 'allow' not in rule:
        rule['allow'] = False
    elif not isinstance(rule['allow'], type(True)):
        raise NonRecoverableError("non-boolean for 'allow' property")
    if 'ports' not in rule:
        raise NonRecoverableError("no ports specified")

#
# processes iptables node for install
#


def make_backup():
    myout = StringIO()
    run("iptables-save", stdout=myout)
    ctx.instance.runtime_properties['backup'] = myout.getvalue()


@operation
def iptables_add(**kwargs):
    env['host_string'] = kwargs['host_ip']
    env['user'] = ctx.node.properties['ssh_user']
    env['key_filename'] = ctx.node.properties['key_filename']

    make_backup()

    if len(ctx.node.properties['firewall_rules']) > 0:
        ichain_name = 'CFY-IFW-'+ctx.instance.id
        ochain_name = 'CFY-OFW-'+ctx.instance.id
        sudo("iptables -N {}".format(ichain_name))
        sudo("iptables -N {}".format(ochain_name))
        ctx.instance.runtime_properties['ichain-name'] = ichain_name
        ctx.instance.runtime_properties['ochain-name'] = ochain_name

        for rule in ctx.node.properties['firewall_rules']:
            ctx.logger.info("running rule")
            _validate_firewall_rule(rule)
            disp = 'ACCEPT' if rule['allow'] else 'DROP'
            if rule['direction'] == 'ingress':
                for port in rule['ports']:
                    sudo("iptables -A {} -p {} -i {} --dport {} -j {}".
                         format(ichain_name, rule['protocol'],
                                rule['interface'], port, disp))
            else:
                for port in rule['ports']:
                    sudo("iptables -A {} -p {} -o {} --dport {} -j {}".
                         format(ochain_name, rule['protocol'],
                                rule['interface'], port, disp))

        sudo("iptables -A INPUT -j {}".format(ichain_name))
        sudo("iptables -A OUTPUT -j {}".format(ochain_name))

        if ctx.node.properties['default_output_policy']:
            sudo("iptables -P OUTPUT {}".format(
                ctx.node.properties['default_output_policy']))
        if ctx.node.properties['default_input_policy']:
            sudo("iptables -P INPUT {}".format(
                ctx.node.properties['default_input_policy']))


@operation
def iptables_remove(**kwargs):
    env['host_string'] = kwargs['host_ip']
    env['user'] = ctx.node.properties['ssh_user']
    env['key_filename'] = ctx.node.properties['key_filename']

    sudo("iptables -D INPUT -j {}".format(
        ctx.instance.runtime_properties['ichain-name']))
    sudo("iptables -D OUTPUT -j {}".format(
        ctx.instance.runtime_properties['ochain-name']))
    sudo("iptables -F {}".format(
        ctx.instance.runtime_properties['ichain-name']))
    sudo("iptables -X {}".format(
        ctx.instance.runtime_properties['ichain-name']))
    sudo("iptables -F {}".format(
        ctx.instance.runtime_properties['ochain-name']))
    sudo("iptables -X {}".format(
        ctx.instance.runtime_properties['ochain-name']))
