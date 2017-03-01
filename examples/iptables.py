from StringIO import StringIO
from cloudify import ctx
from fabric.api import run, sudo, env
from cloudify.exceptions import RecoverableError, NonRecoverableError
from cloudify.state import ctx_parameters as inputs


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


def make_backup():
    myout = StringIO()
    run("iptables-save", stdout=myout)
    ctx.instance.runtime_properties['backup'] = myout.getvalue()


def start():

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
            disp='ACCEPT' if rule['allow'] else 'DROP'
            if rule['direction'] == 'ingress':
                for port in rule['ports']:
                    sudo("iptables -A {} -p {} -i {} --dport {} -j {}".
                         format(ichain_name,rule['protocol'],
                                rule['interface'],port, disp))
            else:
                for port in rule['ports']:
                    sudo("iptables -A {} -p {} -i {} --dport {} -j {}".
                         format(ochain_name,rule['protocol'],
                                rule['interface'],port, disp))
        sudo("iptables -A INPUT -j {}".format(ichain_name))
        sudo("iptables -A OUTPUT -j {}".format(ochain_name))

def stop():
    sudo("iptables -D INPUT -j {}".
         format(ctx.instance.runtime_properties['ichain-name']))
    sudo("iptables -D OUTPUT -j {}".
         format(ctx.instance.runtime_properties['ochain-name']))
    sudo("iptables -F {}".format(ctx.instance.runtime_properties['ichain-name']))
    sudo("iptables -X {}".format(ctx.instance.runtime_properties['ichain-name']))
    sudo("iptables -F {}".format(ctx.instance.runtime_properties['ochain-name']))
    sudo("iptables -X {}".format(ctx.instance.runtime_properties['ochain-name']))
