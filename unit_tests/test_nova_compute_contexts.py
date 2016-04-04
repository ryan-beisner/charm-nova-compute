import platform

from mock import patch
from test_utils import CharmTestCase

import nova_compute_context as context

TO_PATCH = [
    'apt_install',
    'filter_installed_packages',
    'kv',
    'relation_ids',
    'relation_get',
    'related_units',
    'config',
    'log',
    '_save_flag_file',
    'unit_get',
]

NEUTRON_CONTEXT = {
    'network_manager': 'neutron',
    'quantum_auth_strategy': 'keystone',
    'keystone_host': 'keystone_host',
    'auth_port': '5000',
    'auth_protocol': 'https',
    'quantum_url': 'http://quantum_url',
    'service_tenant_name': 'admin',
    'service_username': 'admin',
    'service_password': 'openstack',
    'quantum_security_groups': 'yes',
    'quantum_plugin': 'ovs',
    'auth_host': 'keystone_host',
}


def fake_log(msg, level=None):
    level = level or 'INFO'
    print '[juju test log (%s)] %s' % (level, msg)


class FakeUnitdata(object):

    def __init__(self, **kwargs):
        self.unit_data = {}
        for name, value in kwargs.items():
            self.unit_data[name] = value

    def get(self, key, default=None, record=False):
        return self.unit_data.get(key)

    def set(self, key, value):
        self.unit_data[key] = value

    def flush(self):
        pass


class NovaComputeContextTests(CharmTestCase):

    def setUp(self):
        super(NovaComputeContextTests, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get
        self.log.side_effect = fake_log
        self.host_uuid = 'e46e530d-18ae-4a67-9ff0-e6e2ba7c60a7'
        self.maxDiff = None

    def test_cloud_compute_context_no_relation(self):
        self.relation_ids.return_value = []
        cloud_compute = context.CloudComputeContext()
        self.assertEquals({}, cloud_compute())

    @patch.object(context, '_network_manager')
    def test_cloud_compute_context_restart_trigger(self, nm):
        nm.return_value = None
        cloud_compute = context.CloudComputeContext()
        with patch.object(cloud_compute, 'restart_trigger') as rt:
            rt.return_value = 'footrigger'
            ctxt = cloud_compute()
        self.assertEquals(ctxt.get('restart_trigger'), 'footrigger')

        with patch.object(cloud_compute, 'restart_trigger') as rt:
            rt.return_value = None
            ctxt = cloud_compute()
        self.assertEquals(ctxt.get('restart_trigger'), None)

    @patch.object(context, '_network_manager')
    def test_cloud_compute_volume_context_cinder(self, netman):
        netman.return_value = None
        self.relation_ids.return_value = 'cloud-compute:0'
        self.related_units.return_value = 'nova-cloud-controller/0'
        cloud_compute = context.CloudComputeContext()
        self.test_relation.set({'volume_service': 'cinder'})
        self.assertEquals({'volume_service': 'cinder'}, cloud_compute())

    @patch.object(context, '_network_manager')
    def test_cloud_compute_flatdhcp_context(self, netman):
        netman.return_value = 'flatdhcpmanager'
        self.relation_ids.return_value = 'cloud-compute:0'
        self.related_units.return_value = 'nova-cloud-controller/0'
        self.test_relation.set({
            'network_manager': 'FlatDHCPManager',
            'ec2_host': 'novaapihost'})
        cloud_compute = context.CloudComputeContext()
        ex_ctxt = {
            'network_manager': 'flatdhcpmanager',
            'network_manager_config': {
                'ec2_dmz_host': 'novaapihost',
                'flat_interface': 'eth1'
            },
            'service_protocol': None,
            'service_host': None,
            'service_port': None,
            'admin_tenant_name': None,
            'admin_user': None,
            'admin_password': None,
            'auth_protocol': None,
            'auth_host': None,
            'auth_port': None,
            'api_version': None,
        }
        self.assertEquals(ex_ctxt, cloud_compute())

    @patch.object(context, '_neutron_plugin')
    @patch.object(context, '_neutron_url')
    @patch.object(context, '_network_manager')
    def test_cloud_compute_neutron_context(self, netman, url, plugin):
        self.relation_ids.return_value = 'cloud-compute:0'
        self.related_units.return_value = 'nova-cloud-controller/0'
        netman.return_value = 'neutron'
        plugin.return_value = 'ovs'
        url.return_value = 'http://nova-c-c:9696'
        self.test_relation.set(NEUTRON_CONTEXT)
        cloud_compute = context.CloudComputeContext()
        ex_ctxt = {
            'network_manager': 'neutron',
            'network_manager_config': {
                'api_version': '2.0',
                'auth_protocol': 'https',
                'service_protocol': 'http',
                'auth_port': '5000',
                'keystone_host': 'keystone_host',
                'neutron_admin_auth_url': 'https://keystone_host:5000/v2.0',
                'neutron_admin_password': 'openstack',
                'neutron_admin_tenant_name': 'admin',
                'neutron_admin_username': 'admin',
                'neutron_auth_strategy': 'keystone',
                'neutron_plugin': 'ovs',
                'neutron_security_groups': True,
                'neutron_url': 'http://nova-c-c:9696',
                'service_protocol': 'http',
                'service_port': '5000',
            },
            'service_host': 'keystone_host',
            'admin_tenant_name': 'admin',
            'admin_user': 'admin',
            'admin_password': 'openstack',
            'auth_port': '5000',
            'auth_protocol': 'https',
            'auth_host': 'keystone_host',
            'api_version': '2.0',
            'service_protocol': 'http',
            'service_port': '5000',
        }
        self.assertEquals(ex_ctxt, cloud_compute())
        self._save_flag_file.assert_called_with(
            path='/etc/nova/nm.conf', data='neutron')

    @patch.object(context.NeutronComputeContext, 'network_manager')
    @patch.object(context.NeutronComputeContext, 'plugin')
    def test_neutron_plugin_context_no_setting(self, plugin, nm):
        plugin.return_value = None
        qplugin = context.NeutronComputeContext()
        with patch.object(qplugin, '_ensure_packages'):
            self.assertEquals({}, qplugin())

    def test_libvirt_bin_context_no_migration(self):
        self.kv.return_value = FakeUnitdata(**{'host_uuid': self.host_uuid})
        self.test_config.set('enable-live-migration', False)
        libvirt = context.NovaComputeLibvirtContext()

        self.assertEqual(
            {'libvirtd_opts': '-d',
             'arch': platform.machine(),
             'listen_tls': 0,
             'host_uuid': self.host_uuid}, libvirt())

    def test_libvirt_bin_context_migration_tcp_listen(self):
        self.kv.return_value = FakeUnitdata(**{'host_uuid': self.host_uuid})
        self.test_config.set('enable-live-migration', True)
        libvirt = context.NovaComputeLibvirtContext()

        self.assertEqual(
            {'libvirtd_opts': '-d -l',
             'arch': platform.machine(),
             'listen_tls': 0,
             'host_uuid': self.host_uuid}, libvirt())

    def test_libvirt_disk_cachemodes(self):
        self.kv.return_value = FakeUnitdata(**{'host_uuid': self.host_uuid})
        self.test_config.set('disk-cachemodes', 'file=unsafe,block=none')
        libvirt = context.NovaComputeLibvirtContext()

        self.assertEqual(
            {'libvirtd_opts': '-d',
             'disk_cachemodes': 'file=unsafe,block=none',
             'arch': platform.machine(),
             'listen_tls': 0,
             'host_uuid': self.host_uuid}, libvirt())

    @patch.object(context.uuid, 'uuid4')
    def test_libvirt_new_uuid(self, mock_uuid):
        self.kv.return_value = FakeUnitdata()
        mock_uuid.return_value = '73874c1c-ba48-406d-8d99-ac185d83b9bc'
        libvirt = context.NovaComputeLibvirtContext()
        self.assertEqual(libvirt()['host_uuid'],
                         '73874c1c-ba48-406d-8d99-ac185d83b9bc')

    @patch.object(context.uuid, 'uuid4')
    def test_libvirt_cpu_mode_host_passthrough(self, mock_uuid):
        self.test_config.set('cpu-mode', 'host-passthrough')
        mock_uuid.return_value = 'e46e530d-18ae-4a67-9ff0-e6e2ba7c60a7'
        libvirt = context.NovaComputeLibvirtContext()

        self.assertEqual(libvirt()['cpu_mode'],
                         'host-passthrough')

    @patch.object(context.uuid, 'uuid4')
    def test_libvirt_cpu_mode_default(self, mock_uuid):
        libvirt = context.NovaComputeLibvirtContext()
        self.assertFalse('cpu-mode' in libvirt())

    @patch.object(context.NeutronComputeContext, 'network_manager')
    @patch.object(context.NeutronComputeContext, 'plugin')
    def test_disable_security_groups_true(self, plugin, nm):
        plugin.return_value = "ovs"
        nm.return_value = "neutron"
        self.test_config.set('disable-neutron-security-groups', True)
        qplugin = context.NeutronComputeContext()
        with patch.object(qplugin, '_ensure_packages'):
            self.assertEquals({'disable_neutron_security_groups': True},
                              qplugin())
        self.test_config.set('disable-neutron-security-groups', False)
        qplugin = context.NeutronComputeContext()
        with patch.object(qplugin, '_ensure_packages'):
            self.assertEquals({}, qplugin())

    @patch('subprocess.call')
    def test_host_IP_context(self, _call):
        self.log = fake_log
        self.unit_get.return_value = '172.24.0.79'
        host_ip = context.HostIPContext()
        self.assertEquals({'host_ip': '172.24.0.79'}, host_ip())
        self.unit_get.assert_called_with('private-address')

    @patch.object(context, 'get_ipv6_addr')
    @patch('subprocess.call')
    def test_host_IP_context_ipv6(self, _call, mock_get_ipv6_addr):
        self.log = fake_log
        self.test_config.set('prefer-ipv6', True)
        mock_get_ipv6_addr.return_value = ['2001:db8:0:1::2']
        host_ip = context.HostIPContext()
        self.assertEquals({'host_ip': '2001:db8:0:1::2'}, host_ip())
        self.assertTrue(mock_get_ipv6_addr.called)

    def test_metadata_service_ctxt(self):
        self.relation_ids.return_value = 'neutron-plugin:0'
        self.related_units.return_value = 'neutron-openvswitch/0'
        self.test_relation.set({'metadata-shared-secret': 'shared_secret'})
        metadatactxt = context.MetadataServiceContext()
        self.assertEqual(metadatactxt(), {'metadata_shared_secret':
                                          'shared_secret'})


class DesignateContextTests(CharmTestCase):

    def setUp(self):
        super(DesignateContextTests, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get
        self.host_uuid = 'e46e530d-18ae-4a67-9ff0-e6e2ba7c60a7'

    def test_designate_relation(self):
        self.test_relation.set({})
        designatectxt = context.DesignateContext()
        self.relation_ids.return_value = ['nova-designate:0']
        self.related_units.return_value = 'designate/0'
        self.assertEqual(designatectxt(), {
            'enable_designate': True,
            'notification_driver': 'messaging',
            'notification_topics': 'notifications_designate',
            'notify_on_state_change': 'vm_and_task_state',
        })

    def test_no_designate_relation(self):
        self.test_relation.set({})
        designatectxt = context.DesignateContext()
        self.relation_ids.return_value = []
        self.related_units.return_value = None
        self.assertEqual(designatectxt(), {
            'enable_designate': False,
        })
