# SPDX-FileCopyrightText: 2021-2022 Robin Schneider <ypid@riseup.net>
#
# SPDX-License-Identifier: MIT

"""
NetBox 3.1 custom script to create a network segment on a Firewall.

The script assumes the following exists:

* Site
* Device Role "Firewall" exists.
* VLAN Group per Site
* VLAN/Prefix Role per Site
* Prefix container per Site

If firewall is physical:

* Firewall device with physical interface

The script does the following:

* Reuse or create a VLAN. The VID is derived from the prefix IP Address if a
  new VLAN is created.
* Reuse or create a Prefix. If no Prefix is assigned to the VLAN already the
  next available network block from the Prefix container is created.
* Reuse or create a IP Address for the Firewall Interface.
  If not existing, the first usable IP of the Prefix is used.
* Reuse Interface on the Firewall. Create it only if sub interface for tagged mode.
  Assign the VLAN and IP Address to the Interface.
* If the Firewall is part of a firewall cluster, configure all the cluster nodes.

Bugs:

* IPv6 is not yet supported. But it is simple to implement.
  Just let NetBox pick the next free VLAN and Prefix and drop the need for them
  to have the same numbers. That is just my legacy.
"""

import random

import netaddr

from django.db.utils import IntegrityError
from django.db import transaction
from django.contrib.contenttypes.models import ContentType

from dcim.models import Site, Device, Interface
from dcim.choices import InterfaceTypeChoices, InterfaceModeChoices
from ipam.models import Role, VLANGroup, VLAN, Prefix, IPAddress
from ipam.choices import PrefixStatusChoices, IPAddressRoleChoices
from virtualization.models import VirtualMachine, VMInterface
from extras.scripts import Script, ObjectVar, StringVar, IntegerVar, ChoiceVar, BooleanVar


def _get_next_free_interface_count(vm):
    used_counters = set()
    for interface in vm.interfaces.get_queryset():
        used_counters.add(interface.name)
    for c in range(1, 5000):
        if str(c) not in used_counters:
            return str(c)


def _get_cluster_nodes(cluster):
    """Get cluster nodes based on common config context `cluster` field value."""

    fw_cluster_nodes = []
    for host in VirtualMachine.objects.filter(status='active'):
        if host.get_config_context().get('cluster') == cluster:
            fw_cluster_nodes.append(host.name)
    for host in Device.objects.filter(status='active'):
        if host.get_config_context().get('cluster') == cluster:
            fw_cluster_nodes.append(host.name)

    return sorted(fw_cluster_nodes)

def _manage_ip_address(self, ip_address, log_text_suffix='', role='', delete=False):
    new_ip_address = None
    try:
        # TODO: This does not work in the script? It does not find
        # addresses. Running the same in nbshell finds it.
        new_ip_address = IPAddress.objects.get(
            address=ip_address,
        )
    except:
        #  if delete:
        #      self.log_info(f"Not creating IP address {ip_address}{log_text_suffix}")
        new_ip_address = IPAddress(
            address=ip_address,
        )
        new_ip_address.save()
        self.log_success(f"Created IP address {new_ip_address}{log_text_suffix}")
    else:
        self.log_info(f"IPAddress already exists {new_ip_address}{log_text_suffix}")

    if role and not delete:
        new_ip_address.role = role
        new_ip_address.save()

    if delete:
    #      new_ip_address.delete()
    #      self.log_success(f"Delete IP address {ip_address}{log_text_suffix}")
        self.log_warning(f"You need to delete IP address {ip_address}{log_text_suffix} manually.")

    return new_ip_address

def _get_random_mac_address():
    return '52:54:00:%02x:%02x:%02x' % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255))


class ManageNetworkSegment(Script):
    class Meta:
        name = "Manage network segment"
        description = "Create or delete a network segment."
        commit_default = False

    delete = BooleanVar(
        label="Delete segment (instead of creating)?",
    )
    # Preexisting interfaces has the advantage that they can already be
    # attached to the Firewall VM and thus do not require a reboot of the VM.
    new_interface_wanted = BooleanVar(
        label="Create new interface (instead of reusing existing)?",
        default=False,
    )
    site = ObjectVar(
        model=Site,
        required=False,
    )
    # Derived from other user input in _get_site_prefix_container().
    #  prefix_container = ObjectVar(
    #      model=Prefix,
    #      query_params={
    #          'status': 'container',
    #          'site_id': '$site',
    #      },
    #      required=False,
    #  )
    firewall = ObjectVar(
        model=Device,
        query_params={
            'status': 'active',
            'role': 'firewall',
            'site_id': '$site',
        },
        required=False,
    )
    firewall_vm = ObjectVar(
        label="Firewall VM",
        model=VirtualMachine,
        query_params={
            'status': 'active',
            'role': 'firewall',
            'site_id': '$site',
        },
        required=False,
    )
    parent_interface = ObjectVar(
        model=Interface,
        query_params={
            'type__n': 'virtual',
            'device_id': '$firewall',
        },
        required=False,
    )
    vlan_name = StringVar(
        label="VLAN Name",
        max_length=64,
        regex="^[a-z]+_[a-z0-9_]+$",
    )
    ip_mask = IntegerVar(
        label="IP Address Mask Length",
        min_value=8,
        max_value=24,
        default=24,
    )
    interface_mode = ChoiceVar(
        label="Interface 802.1Q Mode",
        choices=(
            ('access', "Access"),
            ('tagged', "Tagged"),
        ),
    )

    def run(self, data, commit):
        """
        Easy to derive information is accessible via self because it can be
        assumed to be always present. Everything else is factored out to run_
        to enforce access is only possible via self.
        """

        if data['firewall'] is not None:
            self.firewall = data['firewall']
        elif data['firewall_vm'] is not None:
            self.firewall = data['firewall_vm']
        else:
            self.log_failure("Either Firewall or Firewall VM needs to be set.")
            return

        self.prefix_vlan_role = Role.objects.get(
            name=data['vlan_name'].split('_')[0])

        self.site = self.firewall.site
        self.data = data

        self.run_()

    def run_(self):
        site_vlan_group = self._get_vlan_group()
        new_vlan = self._ensure_vlan_exists_and_return(
            site_vlan_group,
        )
        new_prefix = self._ensure_prefix_exists_and_return(
            site_vlan_group,
            new_vlan,
        )

        fw_cluster = self.firewall.get_config_context().get('cluster')

        if fw_cluster is None:
            self._configure_firewall_node(self.firewall, new_vlan, new_prefix, [])
        else:
            fw_cluster_nodes = _get_cluster_nodes(fw_cluster)

            for host in VirtualMachine.objects.filter(status='active'):
                if host.get_config_context().get('cluster') == fw_cluster:
                    self._configure_firewall_node(host, new_vlan, new_prefix, fw_cluster_nodes)
            for host in Device.objects.filter(status='active'):
                if host.get_config_context().get('cluster') == fw_cluster:
                    self._configure_firewall_node(host, new_vlan, new_prefix, fw_cluster_nodes)

        if self.data['delete']:
            new_prefix.delete()
            self.log_success(f"Deleted prefix: {new_prefix}")

            new_vlan.delete()
            self.log_success(f"Deleted VLAN: {new_vlan}")

    def _configure_firewall_node(self, firewall, new_vlan, new_prefix, fw_cluster_nodes):
        if self.data['interface_mode'] == 'tagged' or isinstance(firewall, VirtualMachine):
            #  self.log_info(self.firewall)
            if self.data['parent_interface'] is not None:
                if firewall.platform.slug in ['opnsense', 'pfsense']:
                    new_interface_name = f"{parent_interface.name}_vlan{new_vlan.vid}"
                else:
                    new_interface_name = f"{parent_interface.name}.{new_vlan.vid}"
                new_interface = Interface(
                    name=new_interface_name,
                    parent=parent_interface,
                    device=firewall,
                    type=InterfaceTypeChoices.TYPE_VIRTUAL,
                    mode=InterfaceModeChoices.MODE_TAGGED,
                )
            elif isinstance(firewall, VirtualMachine):
                new_interface_name = self._get_name_for_new_interface(firewall, new_vlan)
                new_interface = VMInterface(
                    name=new_interface_name,
                    virtual_machine=firewall,
                    mode=InterfaceModeChoices.MODE_ACCESS,
                )
            else:
                raise Exception(f"Either parent interface required or the Firewall is virtual.")
            try:
                with transaction.atomic():
                    new_interface.save()
            except IntegrityError:
                self.log_info(f"Interface already exists: {firewall}:{new_interface}")
            else:
                self.log_success(f"Created Interface: {firewall}:{new_interface}")

            if isinstance(firewall, VirtualMachine):
                new_interface = VMInterface.objects.get(
                    virtual_machine=firewall,
                    name=new_interface_name,
                )
            else:
                new_interface = Interface.objects.get(
                    device=firewall,
                    name=new_interface_name,
                )
        else:
            if self.data['parent_interface'] is not None:
                new_interface = parent_interface
                new_interface.description = self.data['vlan_name']
            else:
                raise NotImplementedError(f"Currently not supported.")

        if self.data['interface_mode'] == 'tagged':
            if new_interface.mode != InterfaceModeChoices.MODE_TAGGED:
                raise Exception(f"{firewall}:{new_interface} is not in tagged mode. Please change this manually.")
            new_interface.tagged_vlans.add(new_vlan)
        else:
            if new_interface.mode != InterfaceModeChoices.MODE_ACCESS:
                raise Exception(f"{firewall}:{new_interface} is not in access mode. Please change this manually.")
            new_interface.untagged_vlan = new_vlan

        if isinstance(firewall, VirtualMachine):
            if new_interface.mac_address == '':
                new_interface.mac_address = _get_random_mac_address()
                self.log_success(f"Set MAC address of {firewall}:{new_interface} to {new_interface.mac_address}")

        self._manage_ip_addresses_on_fw_interface(firewall, new_interface, new_prefix, fw_cluster_nodes)

        if self.data['delete']:
            new_interface.mode = ""
            new_interface.untagged_vlan = None
            self.log_success(f"Unset VLAN on {firewall}:{new_interface}")
        else:
            new_interface.save()
            self.log_success(f"Ensured IP addresses are up-to-date: {firewall}:{new_interface}")

    def _manage_ip_addresses_on_fw_interface(self, firewall, interface, new_prefix, fw_cluster_nodes):
        interface.ip_addresses.clear()

        if len(fw_cluster_nodes) >= 1:
            if fw_cluster_nodes[0] == firewall.name:
                new_vip_address = self._manage_first_ip_address_from_prefix(
                    new_prefix,
                    log_text_suffix=f" for {firewall}:{interface}.",
                    role='carp',
                )
                if not self.data['delete']:
                    interface.ip_addresses.add(new_vip_address)

            new_ip = str(new_prefix.prefix[-5 + fw_cluster_nodes.index(firewall.name)]) + '/' + str(new_prefix.prefix.netmask.netmask_bits())
            new_vip_address = _manage_ip_address(
                self,
                new_ip,
                log_text_suffix=f" for {firewall}:{interface}.",
            )
            if not self.data['delete']:
                interface.ip_addresses.add(new_vip_address)
        else:
            new_ip_address = self._manage_first_ip_address_from_prefix(
                new_prefix,
                log_text_suffix=f" for {firewall}:{interface}.",
            )
            if not self.data['delete']:
                interface.ip_addresses.add(new_ip_address)

    def _ensure_vlan_exists_and_return(self, site_vlan_group):
        new_prefix_str = None
        new_vlan = VLAN.objects.filter(
            name=self.data['vlan_name'],
            group=site_vlan_group,
        )
        if new_vlan.count() == 1:
            new_vlan = new_vlan[0]
            self.log_info(f"VLAN already exists (found based on name, group): {new_vlan}")
        else:
            #  if self.data['vlan_id']:
            new_prefix_str = self._get_first_available_prefix_variable_mask_length()
            self.log_info(f"Selected next free prefix: {new_prefix_str}.")
            new_vlan_id = self._derive_vlan_id_from_prefix_address(new_prefix_str)

            new_vlan = VLAN.objects.filter(
                vid=new_vlan_id,
                group=site_vlan_group,
            )
            if new_vlan.count() == 1:
                new_vlan = new_vlan[0]
                self.log_info(f"VLAN already exists (found based on VID, group): {new_vlan}")

            else:
                new_vlan = VLAN(
                    vid=new_vlan_id,
                    name=self.data['vlan_name'],
                    group=site_vlan_group,
                )
                new_vlan.save()
                self.log_success(f"Created VLAN: {new_vlan}")

        if self.prefix_vlan_role is not None:
            new_vlan.role = self.prefix_vlan_role
            new_vlan.save()

        return new_vlan

    def _ensure_prefix_exists_and_return(self, site_vlan_group, new_vlan):
        new_prefix = Prefix.objects.filter(
            vlan__vid=new_vlan.vid,
            vlan__group=site_vlan_group,
        )
        if new_prefix.count() != 0:
            new_prefix = new_prefix[0]
            self.log_info(f"Prefix already exists (found based on VLAN relation): {new_prefix}")
        else:
            new_prefix_str = self._derive_prefix_address_from_vlan_id(new_vlan.vid)

            new_prefix = Prefix.objects.filter(
                prefix=new_prefix_str,
            )
            if new_prefix.count() != 0:
                new_prefix = new_prefix[0]
                self.log_info(f"Prefix already exists (found based on prefix relation): {new_prefix}")
            else:
                new_prefix = Prefix(
                    prefix=new_prefix_str,
                )
                try:
                    with transaction.atomic():
                        new_prefix.save()
                except IntegrityError:
                    self.log_info(f"Prefix already exists: {new_prefix}")
                    new_prefix = Prefix.objects.get(
                        prefix=new_prefix_str,
                    )
                else:
                    self.log_success(f"Created prefix: {new_prefix}")

        # Avoid the redundancy with the VLAN.
        #  new_prefix.role = self.prefix_vlan_role

        new_prefix.site = self.site
        new_prefix.vlan = new_vlan
        new_prefix.save()

        # Workaround for new_prefix which is a str.
        new_prefix = Prefix.objects.get(pk=new_prefix.pk)

        return new_prefix

    def _manage_first_ip_address_from_prefix(self, new_prefix, log_text_suffix='', role=None):
        prefix_ip_addresses = new_prefix.prefix.__iter__()

        if new_prefix.family == 4:
            # Skip network ID.
            next(prefix_ip_addresses)

        prefix_ip_address = next(prefix_ip_addresses)
        prefix_ip_address = f'{prefix_ip_address}/{new_prefix.prefix.prefixlen}'

        return _manage_ip_address(self, prefix_ip_address, log_text_suffix, role, self.data['delete'])

    def _get_site_prefix_container(self):
        site_prefix_container = Prefix.objects.filter(
            site=self.site,
            status=PrefixStatusChoices.STATUS_CONTAINER,
        )
        if site_prefix_container.count() != 1:
            #  if self.data['prefix_vlan_role'] is not None:
            site_prefix_container = Prefix.objects.filter(
                #  role__name=self.data['prefix_vlan_role'],
                # Workaround:
                id=1,
                site=self.site,
                status=PrefixStatusChoices.STATUS_CONTAINER,
            )
            if site_prefix_container.count() != 1:
                raise Exception(f"{site_prefix_container.count()} prefix containers exist for this site. Expected 1.")
        return site_prefix_container[0]

    def _get_vlan_group(self):
        site_vlan_group = VLANGroup.objects.filter(
            name=self.site.name,
            scope_type=ContentType.objects.get_by_natural_key('dcim', 'site'),
            scope_id=self.site.id,
        )
        if site_vlan_group.count() != 1:
            raise Exception(f"{site_vlan_group.count()} VLAN groups containers exist for this site. Expected 1.")
        return site_vlan_group[0]

    def _get_first_available_prefix_variable_mask_length(self):
        site_prefix_container = self._get_site_prefix_container()
        available_prefixes = site_prefix_container.get_available_prefixes()
        for available_prefix in available_prefixes.iter_cidrs():
            if self.data['ip_mask'] >= available_prefix.prefixlen:
                return '{}/{}'.format(
                    available_prefix.network,
                    self.data['ip_mask'],
                )
                break

    def _derive_vlan_id_from_prefix_address(self, prefix_address):
        """172.23.42.0/24 -> VLAN ID: 2342"""

        new_vlan_id = 0
        for ip_octet in prefix_address.split('/')[0].split('.')[1:3]:
            new_vlan_id = 100 * new_vlan_id + int(ip_octet)
        self.log_info(f"Derived VLAN ID {new_vlan_id} from prefix {prefix_address}.")
        return new_vlan_id

    def _derive_prefix_address_from_vlan_id(self, vlan_id):
        """VLAN ID: 2342 -> 172.23.42.0/24 (depending on prefix container)"""

        site_prefix_container = self._get_site_prefix_container()

        ipv4_octets = (
            str(site_prefix_container.prefix).split('.')[0],
            str(int(vlan_id / 100)),
            str(vlan_id % 100),
            '0',
        )

        return '.'.join(ipv4_octets) + '/' + str(self.data['ip_mask'])

    def _get_name_for_new_interface(self, firewall, vlan):
        try:
            interface = firewall.interfaces.get_queryset().get(untagged_vlan__id=vlan.id)
        except:
            pass
        else:
            self.log_info(f"Interface {interface.name} already exists (found based on untagged VLAN): {vlan}")
            return interface.name

        interface = firewall.interfaces.get_queryset().filter(ip_addresses__address='').first()
        if interface:
            self.log_info(f"Reusing next free existing interface {interface.name}")
            return interface.name

        return _get_next_free_interface_count(firewall)


class GenVmInterfaces(Script):
    class Meta:
        name = "Gen VM interfaces"
        description = "Generate interfaces for a VM so that networks can be attached while the VM is running. Mostly interesting for firewall VMs."
        commit_default = True

    site = ObjectVar(
        model=Site,
        required=False,
    )
    vm = ObjectVar(
        model=VirtualMachine,
        label="VM",
        query_params={
            'status': 'active',
            'site_id': '$site',
        },
    )
    number_of_interfaces = IntegerVar(
        label="Number of interfaces to create",
        default=10,
    )

    def run(self, data, commit):
        for _ in range(data['number_of_interfaces']):
            new_interface = VMInterface(
                name=_get_next_free_interface_count(data['vm']),
                virtual_machine=data['vm'],
                mode=InterfaceModeChoices.MODE_ACCESS,
                mac_address = _get_random_mac_address()
            )
            new_interface.save()
            self.log_success(f"Created {data['vm']}:{new_interface} with MAC address {new_interface.mac_address}.")


class CopyVmInterfaces(Script):
    class Meta:
        name = "Copy interfaces to VM"
        description = "Copy interfaces from one leader cluster node VM to a follower cluster node VM while taking care for MAC addresses, VIPs and VLANs."
        commit_default = True

    site = ObjectVar(
        model=Site,
        required=False,
    )
    leader_vm = ObjectVar(
        model=VirtualMachine,
        label="Source VM",
        query_params={
            'status': 'active',
            'site_id': '$site',
        },
    )
    follower_vm = ObjectVar(
        model=VirtualMachine,
        label="Target VM",
        query_params={
            'status': 'active',
            'site_id': '$site',
        },
    )

    def run(self, data, commit):
        for leader_int in data['leader_vm'].interfaces.get_queryset():
            try:
                new_interface = VMInterface.objects.get(
                    virtual_machine=data['follower_vm'],
                    name=leader_int.name)
            except:
                new_interface = VMInterface(
                    name=leader_int.name,
                    virtual_machine=data['follower_vm'],
                )
                new_interface.save()

            new_interface.mac_address = _get_random_mac_address()
            new_interface.mode = leader_int.mode
            new_interface.untagged_vlan = leader_int.untagged_vlan

            for ip_addr in leader_int.ip_addresses.all():
                if ip_addr.role == 'carp':
                    continue

                new_ip_address = _manage_ip_address(
                    self,
                    str(str(ip_addr.address.ip + 1) + "/" + str(ip_addr.address.netmask.netmask_bits())),
                    log_text_suffix=f" for {data['follower_vm']}:{new_interface}.",
                )
                new_ip_address.save()
                new_interface.ip_addresses.add(new_ip_address)

                # FIXME
                #  if ip_addr == data['leader_vm'].primary_ip:
                #      data['follower_vm'].primary_ip = new_ip_address
                #      data['follower_vm'].save()

            new_interface.save()
            self.log_success(f"Created {data['follower_vm']}:{new_interface} with MAC address {new_interface.mac_address}.")


class TagAllUsedVlansOnUplink(Script):
    class Meta:
        name = "Tag all used VLANs on uplink"
        description = "All used VLANs on a switch must go thought the uplink usually."
        commit_default = True

    site = ObjectVar(
        model=Site,
        required=False,
    )
    switch = ObjectVar(
        model=Device,
        label="Switch",
        query_params={
            'status': 'active',
            'role': 'switch',
            'site_id': '$site',
        },
    )

    def run(self, data, commit):
        uplink_int = data['switch'].interfaces.get_queryset().get(description='Uplink')
        for sw_int in data['switch'].interfaces.get_queryset():
            if sw_int.description == 'Uplink':
                continue

            for vlan in [sw_int.untagged_vlan] + list(sw_int.tagged_vlans.get_queryset()):
                if vlan is not None:
                    uplink_int.tagged_vlans.add(vlan)
