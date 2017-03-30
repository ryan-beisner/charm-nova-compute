# Copyright 2014-2015 Canonical Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import OrderedDict
import importlib
import os
import platform
import re
import six
import time
import subprocess
from tempfile import NamedTemporaryFile
from yaml import safe_load

from charmhelpers.core.host import (
    lsb_release
)
from charmhelpers.core.hookenv import (
    config,
    log,
    DEBUG,
)
from charmhelpers.fetch import SourceConfigError, GPGKeyError, UnhandledSource

PROPOSED_POCKET = (
    "# Proposed\n"
    "deb http://archive.ubuntu.com/ubuntu {}-proposed main universe "
    "multiverse restricted\n")
PROPOSED_PORTS_POCKET = (
    "# Proposed\n"
    "deb http://ports.ubuntu.com/ubuntu-ports {}-proposed main universe "
    "multiverse restricted\n")
# Only supports 64bit and ppc64 at the moment.
ARCH_TO_PROPOSED_POCKET = {
    'x86_64': PROPOSED_POCKET,
    'ppc64le': PROPOSED_PORTS_POCKET,
}
CLOUD_ARCHIVE_URL = "http://ubuntu-cloud.archive.canonical.com/ubuntu"
CLOUD_ARCHIVE_KEY_ID = '5EDB1B62EC4926EA'
CLOUD_ARCHIVE = """# Ubuntu Cloud Archive
deb http://ubuntu-cloud.archive.canonical.com/ubuntu {} main
"""
CLOUD_ARCHIVE_POCKETS = {
    # Folsom
    'folsom': 'precise-updates/folsom',
    'folsom/updates': 'precise-updates/folsom',
    'precise-folsom': 'precise-updates/folsom',
    'precise-folsom/updates': 'precise-updates/folsom',
    'precise-updates/folsom': 'precise-updates/folsom',
    'folsom/proposed': 'precise-proposed/folsom',
    'precise-folsom/proposed': 'precise-proposed/folsom',
    'precise-proposed/folsom': 'precise-proposed/folsom',
    # Grizzly
    'grizzly': 'precise-updates/grizzly',
    'grizzly/updates': 'precise-updates/grizzly',
    'precise-grizzly': 'precise-updates/grizzly',
    'precise-grizzly/updates': 'precise-updates/grizzly',
    'precise-updates/grizzly': 'precise-updates/grizzly',
    'grizzly/proposed': 'precise-proposed/grizzly',
    'precise-grizzly/proposed': 'precise-proposed/grizzly',
    'precise-proposed/grizzly': 'precise-proposed/grizzly',
    # Havana
    'havana': 'precise-updates/havana',
    'havana/updates': 'precise-updates/havana',
    'precise-havana': 'precise-updates/havana',
    'precise-havana/updates': 'precise-updates/havana',
    'precise-updates/havana': 'precise-updates/havana',
    'havana/proposed': 'precise-proposed/havana',
    'precise-havana/proposed': 'precise-proposed/havana',
    'precise-proposed/havana': 'precise-proposed/havana',
    # Icehouse
    'icehouse': 'precise-updates/icehouse',
    'icehouse/updates': 'precise-updates/icehouse',
    'precise-icehouse': 'precise-updates/icehouse',
    'precise-icehouse/updates': 'precise-updates/icehouse',
    'precise-updates/icehouse': 'precise-updates/icehouse',
    'icehouse/proposed': 'precise-proposed/icehouse',
    'precise-icehouse/proposed': 'precise-proposed/icehouse',
    'precise-proposed/icehouse': 'precise-proposed/icehouse',
    # Juno
    'juno': 'trusty-updates/juno',
    'juno/updates': 'trusty-updates/juno',
    'trusty-juno': 'trusty-updates/juno',
    'trusty-juno/updates': 'trusty-updates/juno',
    'trusty-updates/juno': 'trusty-updates/juno',
    'juno/proposed': 'trusty-proposed/juno',
    'trusty-juno/proposed': 'trusty-proposed/juno',
    'trusty-proposed/juno': 'trusty-proposed/juno',
    # Kilo
    'kilo': 'trusty-updates/kilo',
    'kilo/updates': 'trusty-updates/kilo',
    'trusty-kilo': 'trusty-updates/kilo',
    'trusty-kilo/updates': 'trusty-updates/kilo',
    'trusty-updates/kilo': 'trusty-updates/kilo',
    'kilo/proposed': 'trusty-proposed/kilo',
    'trusty-kilo/proposed': 'trusty-proposed/kilo',
    'trusty-proposed/kilo': 'trusty-proposed/kilo',
    # Liberty
    'liberty': 'trusty-updates/liberty',
    'liberty/updates': 'trusty-updates/liberty',
    'trusty-liberty': 'trusty-updates/liberty',
    'trusty-liberty/updates': 'trusty-updates/liberty',
    'trusty-updates/liberty': 'trusty-updates/liberty',
    'liberty/proposed': 'trusty-proposed/liberty',
    'trusty-liberty/proposed': 'trusty-proposed/liberty',
    'trusty-proposed/liberty': 'trusty-proposed/liberty',
    # Mitaka
    'mitaka': 'trusty-updates/mitaka',
    'mitaka/updates': 'trusty-updates/mitaka',
    'trusty-mitaka': 'trusty-updates/mitaka',
    'trusty-mitaka/updates': 'trusty-updates/mitaka',
    'trusty-updates/mitaka': 'trusty-updates/mitaka',
    'mitaka/proposed': 'trusty-proposed/mitaka',
    'trusty-mitaka/proposed': 'trusty-proposed/mitaka',
    'trusty-proposed/mitaka': 'trusty-proposed/mitaka',
    # Newton
    'newton': 'xenial-updates/newton',
    'newton/updates': 'xenial-updates/newton',
    'xenial-newton': 'xenial-updates/newton',
    'xenial-newton/updates': 'xenial-updates/newton',
    'xenial-updates/newton': 'xenial-updates/newton',
    'newton/proposed': 'xenial-proposed/newton',
    'xenial-newton/proposed': 'xenial-proposed/newton',
    'xenial-proposed/newton': 'xenial-proposed/newton',
    # Ocata
    'ocata': 'xenial-updates/ocata',
    'ocata/updates': 'xenial-updates/ocata',
    'xenial-ocata': 'xenial-updates/ocata',
    'xenial-ocata/updates': 'xenial-updates/ocata',
    'xenial-updates/ocata': 'xenial-updates/ocata',
    'ocata/proposed': 'xenial-proposed/ocata',
    'xenial-ocata/proposed': 'xenial-proposed/ocata',
    'xenial-ocata/newton': 'xenial-proposed/ocata',
}

# The order of this list is very important. Handlers should be listed in from
# least- to most-specific URL matching.
FETCH_HANDLERS = (
    'charmhelpers.fetch.archiveurl.ArchiveUrlFetchHandler',
    'charmhelpers.fetch.bzrurl.BzrUrlFetchHandler',
    'charmhelpers.fetch.giturl.GitUrlFetchHandler',
)

APT_NO_LOCK = 100  # The return code for "couldn't acquire lock" in APT.
CMD_RETRY_DELAY = 10  # Wait 10 seconds between command retries.
CMD_RETRY_COUNT = 30  # Retry a failing fatal command X times.




# XXX: hack for conflict/rebase
#      /!\ DO NOT LAND WITH THIS IN PLACE
APT_NO_LOCK_RETRY_DELAY = CMD_RETRY_DELAY
APT_NO_LOCK_RETRY_COUNT = CMD_RETRY_COUNT


def filter_installed_packages(packages):
    """Return a list of packages that require installation."""
    cache = apt_cache()
    _pkgs = []
    for package in packages:
        try:
            p = cache[package]
            p.current_ver or _pkgs.append(package)
        except KeyError:
            log('Package {} has no installation candidate.'.format(package),
                level='WARNING')
            _pkgs.append(package)
    return _pkgs


def apt_cache(in_memory=True, progress=None):
    """Build and return an apt cache."""
    from apt import apt_pkg
    apt_pkg.init()
    if in_memory:
        apt_pkg.config.set("Dir::Cache::pkgcache", "")
        apt_pkg.config.set("Dir::Cache::srcpkgcache", "")
    return apt_pkg.Cache(progress)


def apt_install(packages, options=None, fatal=False):
    """Install one or more packages."""
    if options is None:
        options = ['--option=Dpkg::Options::=--force-confold']

    cmd = ['apt-get', '--assume-yes']
    cmd.extend(options)
    cmd.append('install')
    if isinstance(packages, six.string_types):
        cmd.append(packages)
    else:
        cmd.extend(packages)
    log("Installing {} with options: {}".format(packages,
                                                options))
    _run_apt_command(cmd, fatal)


def apt_upgrade(options=None, fatal=False, dist=False):
    """Upgrade all packages."""
    if options is None:
        options = ['--option=Dpkg::Options::=--force-confold']

    cmd = ['apt-get', '--assume-yes']
    cmd.extend(options)
    if dist:
        cmd.append('dist-upgrade')
    else:
        cmd.append('upgrade')
    log("Upgrading with options: {}".format(options))
    _run_apt_command(cmd, fatal)


def apt_update(fatal=False):
    """Update local apt cache."""
    cmd = ['apt-get', 'update']
    _run_apt_command(cmd, fatal)


def apt_purge(packages, fatal=False):
    """Purge one or more packages."""
    cmd = ['apt-get', '--assume-yes', 'purge']
    if isinstance(packages, six.string_types):
        cmd.append(packages)
    else:
        cmd.extend(packages)
    log("Purging {}".format(packages))
    _run_apt_command(cmd, fatal)


def apt_mark(packages, mark, fatal=False):
    """Flag one or more packages using apt-mark."""
    log("Marking {} as {}".format(packages, mark))
    cmd = ['apt-mark', mark]
    if isinstance(packages, six.string_types):
        cmd.append(packages)
    else:
        cmd.extend(packages)

    if fatal:
        subprocess.check_call(cmd, universal_newlines=True)
    else:
        subprocess.call(cmd, universal_newlines=True)


def apt_hold(packages, fatal=False):
    return apt_mark(packages, 'hold', fatal=fatal)


def apt_unhold(packages, fatal=False):
    return apt_mark(packages, 'unhold', fatal=fatal)


def import_key(keyid):
    """Import a key in either ASCII Armor or Radix64 format.

    `keyid` is either the keyid to fetch from a PGP server, or
    the key in ASCII armor foramt.

    :param keyid: String of key (or key id).
    :raises: GPGKeyError if the key could not be imported
    """
    key = keyid.strip()
    if (key.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----') and
            key.endswith('-----END PGP PUBLIC KEY BLOCK-----')):
        log("PGP key found (looks like ASCII Armor format)", level=DEBUG)
        log("Importing ASCII Armor PGP key", level=DEBUG)
        with NamedTemporaryFile() as keyfile:
            with open(keyfile.name, 'w') as fd:
                fd.write(key)
                fd.write("\n")
            cmd = ['apt-key', 'add', keyfile.name]
            try:
                subprocess.check_call(cmd)
            except subprocess.CalledProcessError:
                error = "Error importing PGP key '{}'".format(key)
                log(error)
                raise GPGKeyError(error)
    else:
        log("PGP key found (looks like Radix64 format)", level=DEBUG)
        log("Importing PGP key from keyserver", level=DEBUG)
        cmd = ['apt-key', 'adv', '--keyserver',
               'hkp://keyserver.ubuntu.com:80', '--recv-keys', key]
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError:
            error = "Error importing PGP key '{}'".format(key)
            log(error)
            raise GPGKeyError(error)


def add_source(source, key=None, fail_invalid=False):
    """Add a package source to this system.

    @param source: a URL or sources.list entry, as supported by
    add-apt-repository(1). Examples::

        ppa:charmers/example
        deb https://stub:key@private.example.com/ubuntu trusty main

    In addition:
        'proposed:' may be used to enable the standard 'proposed'
        pocket for the release.
        'cloud:' may be used to activate official cloud archive pockets,
        such as 'cloud:icehouse'
        'distro' may be used as a noop

    Full list of source specifications supported by the function are:

    'distro': A NOP; i.e. it has no effect.
    'proposed': the proposed deb spec [2] is wrtten to
      /etc/apt/sources.list/proposed
    'distro-proposed': adds <version>-proposed to the debs [2]
    'ppa:<ppa-name>': add-apt-repository --yes <ppa_name>
    'deb <deb-spec>': add-apt-repository --yes deb <deb-spec>
    'http://....': add-apt-repository --yes http://...
    'cloud-archive:<spec>': add-apt-repository -yes cloud-archive:<spec>
    'cloud:<release>[-staging]': specify a Cloud Archive pocket <release> with
      optional staging version.  If staging is used then the staging PPA [2]
      with be used.  If staging is NOT used then the cloud archive [3] will be
      added, and the 'ubuntu-cloud-keyring' package will be added for the
      current distro.

    Otherwise the source is not recognised and this is logged to the juju log.
    However, no error is raised, unless sys_error_on_exit is True.

    [1] deb http://ubuntu-cloud.archive.canonical.com/ubuntu {} main
        where {} is replaced with the derived pocket name.
    [2] deb http://archive.ubuntu.com/ubuntu {}-proposed \
        main universe multiverse restricted
        where {} is replaced with the lsb_release codename (e.g. xenial)
    [3] deb http://ubuntu-cloud.archive.canonical.com/ubuntu <pocket>
        to /etc/apt/sources.list.d/cloud-archive-list

    @param key: A key to be added to the system's APT keyring and used
    to verify the signatures on packages. Ideally, this should be an
    ASCII format GPG public key including the block headers. A GPG key
    id may also be used, but be aware that only insecure protocols are
    available to retrieve the actual public key from a public keyserver
    placing your Juju environment at risk. ppa and cloud archive keys
    are securely added automtically, so sould not be provided.

    @param fail_invalid: (boolean) if True, then the function raises a
    SourceConfigError is there is no matching installation source.

    @raises SourceConfigError() if for cloud:<pocket>, the <pocket> is not a
    valid pocket in CLOUD_ARCHIVE_POCKETS
    """
    _mapping = OrderedDict([
        (r"^distro$", lambda: None),  # This is a NOP
        (r"^(?:proposed|distro-proposed)$", _add_proposed),
        (r"^cloud-archive:(.*)$", _add_apt_repository),
        (r"^((?:deb |http:|https:|ppa:).*)$", _add_apt_repository),
        (r"^cloud:(.*)-(.*)\/staging$", _add_cloud_staging),
        (r"^cloud:(.*)-(.*)$", _add_cloud_distro_check),
        (r"^cloud:(.*)$", _add_cloud_pocket),
    ])
    if source is None:
        source = ''
    for r, fn in six.iteritems(_mapping):
        m = re.match(r, source)
        if m:
            # call the assoicated function with the captured groups
            # raises SourceConfigError on error.
            fn(*m.groups())
            if key:
                try:
                    import_key(key)
                except GPGKeyError as e:
                    raise SourceConfigError(str(e))
            break
    else:
        # nothing matched.  log an error and maybe sys.exit
        err = "Unknown source: {!r}".format(source)
        log(err)
        if fail_invalid:
            raise SourceConfigError(err)


def _add_proposed():
    """Add the PROPOSED_POCKET as /etc/apt/source.list.d/proposed.list

    Uses lsb_release()['DISTRIB_CODENAME'] to determine the correct staza for
    the deb line.

    For intel architecutres PROPOSED_POCKET is used for the release, but for
    other architectures PROPOSED_PORTS_POCKET is used for the release.
    """
    release = lsb_release()['DISTRIB_CODENAME']
    arch = platform.machine()
    if arch not in six.iterkeys(ARCH_TO_PROPOSED_POCKET):
        raise SourceConfigError("Arch {} not supported for (distro-)proposed"
                                .format(arch))
    with open('/etc/apt/sources.list.d/proposed.list', 'w') as apt:
        apt.write(ARCH_TO_PROPOSED_POCKET[arch].format(release))


def _add_apt_repository(spec):
    """Add the spec using add_apt_repository

    :param spec: the parameter to pass to add_apt_repository
    """
    subprocess.check_call(['add-apt-repository', '--yes', spec])


def _add_cloud_pocket(pocket):
    """Add a cloud pocket as /etc/apt/sources.d/cloud-archive.list

    Note that this overwrites the existing file if there is one.

    This function also converts the simple pocket in to the actual pocket using
    the CLOUD_ARCHIVE_POCKETS mapping.

    :param pocket: string representing the pocket to add a deb spec for.
    :raises: SourceConfigError if the cloud pocket doesn't exist or the
        requested release doesn't match the current distro version.
    """
    apt_install(filter_installed_packages(['ubuntu-cloud-keyring']),
                fatal=True)
    if pocket not in CLOUD_ARCHIVE_POCKETS:
        raise SourceConfigError(
            'Unsupported cloud: source option %s' %
            pocket)
    actual_pocket = CLOUD_ARCHIVE_POCKETS[pocket]
    with open('/etc/apt/sources.list.d/cloud-archive.list', 'w') as apt:
        apt.write(CLOUD_ARCHIVE.format(actual_pocket))


def _add_cloud_staging(cloud_archive_release, openstack_release):
    """Add the cloud staging repository which is in
    ppa:ubuntu-cloud-archive/<openstack_release>-staging

    This function checks that the cloud_archive_release matches the current
    codename for the distro that charm is being installed on.

    :param cloud_archive_release: string, codename for the release.
    :param openstack_release: String, codename for the openstack release.
    :raises: SourceConfigError if the cloud_archive_release doesn't match the
        current version of the os.
    """
    _verify_is_ubuntu_rel(cloud_archive_release, openstack_release)
    ppa = 'ppa:ubuntu-cloud-archive/{}-staging'.format(openstack_release)
    cmd = 'add-apt-repository -y {}'.format(ppa)
    subprocess.check_call(cmd.split(' '))


def _add_cloud_distro_check(cloud_archive_release, openstack_release):
    """Add the cloud pocket, but also check the cloud_archive_release against
    the current distro, and use the openstack_release as the full lookup.

    This just calls _add_cloud_pocket() with the openstack_release as pocket
    to get the correct cloud-archive.list for dpkg to work with.

    :param cloud_archive_release:String, codename for the distro release.
    :param openstack_release: String, spec for the release to look up in the
        CLOUD_ARCHIVE_POCKETS
    :raises: SourceConfigError if this is the wrong distro, or the pocket spec
        doesn't exist.
    """
    _verify_is_ubuntu_rel(cloud_archive_release, openstack_release)
    _add_cloud_pocket("{}-{}".format(cloud_archive_release, openstack_release))


def _verify_is_ubuntu_rel(release, os_release):
    """Verify that the release is in the same as the current ubuntu release.

    :param release: String, lowercase for the release.
    :param os_release: String, the os_release being asked for
    :raises: SourceConfigError if the release is not the same as the ubuntu
        release.
    """
    ubuntu_rel = lsb_release()['DISTRIB_CODENAME']
    if release != ubuntu_rel:
        raise SourceConfigError(
            'Invalid Cloud Archive release specified: {}-{} on this Ubuntu'
            'version ({})'.format(release, os_release, ubuntu_rel))


def configure_sources(update=False,
                      sources_var='install_sources',
                      keys_var='install_keys'):
    """
    Configure multiple sources from charm configuration.

    The lists are encoded as yaml fragments in the configuration.
    The frament needs to be included as a string. Sources and their
    corresponding keys are of the types supported by add_source().

    Example config:
        install_sources: |
          - "ppa:foo"
          - "http://example.com/repo precise main"
        install_keys: |
          - null
          - "a1b2c3d4"

    Note that 'null' (a.k.a. None) should not be quoted.
    """
    sources = safe_load((config(sources_var) or '').strip()) or []
    keys = safe_load((config(keys_var) or '').strip()) or None

    if isinstance(sources, six.string_types):
        sources = [sources]

    if keys is None:
        for source in sources:
            add_source(source, None)
    else:
        if isinstance(keys, six.string_types):
            keys = [keys]

        if len(sources) != len(keys):
            raise SourceConfigError(
                'Install sources and keys lists are different lengths')
        for source, key in zip(sources, keys):
            add_source(source, key)
    if update:
        apt_update(fatal=True)


def install_remote(source, *args, **kwargs):
    """
    Install a file tree from a remote source

    The specified source should be a url of the form:
        scheme://[host]/path[#[option=value][&...]]

    Schemes supported are based on this modules submodules.
    Options supported are submodule-specific.
    Additional arguments are passed through to the submodule.

    For example::

        dest = install_remote('http://example.com/archive.tgz',
                              checksum='deadbeef',
                              hash_type='sha1')

    This will download `archive.tgz`, validate it using SHA1 and, if
    the file is ok, extract it and return the directory in which it
    was extracted.  If the checksum fails, it will raise
    :class:`charmhelpers.core.host.ChecksumError`.
    """
    # We ONLY check for True here because can_handle may return a string
    # explaining why it can't handle a given source.
    handlers = [h for h in plugins() if h.can_handle(source) is True]
    for handler in handlers:
        try:
            return handler.install(source, *args, **kwargs)
        except UnhandledSource as e:
            log('Install source attempt unsuccessful: {}'.format(e),
                level='WARNING')
    raise UnhandledSource("No handler found for source {}".format(source))


def install_from_config(config_var_name):
    charm_config = config()
    source = charm_config[config_var_name]
    return install_remote(source)


def plugins(fetch_handlers=None):
    if not fetch_handlers:
        fetch_handlers = FETCH_HANDLERS
    plugin_list = []
    for handler_name in fetch_handlers:
        package, classname = handler_name.rsplit('.', 1)
        try:
            handler_class = getattr(
                importlib.import_module(package),
                classname)
            plugin_list.append(handler_class())
        except NotImplementedError:
            # Skip missing plugins so that they can be ommitted from
            # installation if desired
            log("FetchHandler {} not found, skipping plugin".format(
                handler_name))
    return plugin_list


def _run_with_retries(cmd, max_retries=CMD_RETRY_COUNT, retry_exitcodes=(1,),
                      retry_message="", cmd_env=None):
    """Run a command and retry until success or max_retries is reached.

    :param: cmd: str: The apt command to run.
    :param: max_retries: int: The number of retries to attempt on a fatal
        command. Defaults to CMD_RETRY_COUNT.
    :param: retry_exitcodes: tuple: Optional additional exit codes to retry.
        Defaults to retry on exit code 1.
    :param: retry_message: str: Optional log prefix emitted during retries.
    :param: cmd_env: dict: Environment variables to add to the command run.
    """

    env = os.environ.copy()
    if cmd_env:
        env.update(cmd_env)

    if not retry_message:
        retry_message = "Failed executing '{}'".format(" ".join(cmd))
    retry_message += ". Will retry in {} seconds".format(CMD_RETRY_DELAY)

    retry_count = 0
    result = None

    retry_results = (None,) + retry_exitcodes
    while result in retry_results:
        try:
            result = subprocess.check_call(cmd, env=env)
        except subprocess.CalledProcessError as e:
            retry_count = retry_count + 1
            if retry_count > max_retries:
                raise
            result = e.returncode
            log(retry_message)
            time.sleep(CMD_RETRY_DELAY)


def _run_apt_command(cmd, fatal=False):
    """
    Run an APT command, checking output and retrying if the fatal flag is set
    to True.

    :param: cmd: str: The apt command to run.
    :param: fatal: bool: Whether the command's output should be checked and
        retried.
    """
    # Provide DEBIAN_FRONTEND=noninteractive if not present in the environment.
    cmd_env = {
        'DEBIAN_FRONTEND': os.environ.get('DEBIAN_FRONTEND', 'noninteractive')}

    if fatal:
        retry_count = 0
        result = None

        # If the command is considered "fatal", we need to retry if the apt
        # lock was not acquired.

        while result is None or result == APT_NO_LOCK:
            try:
                env = os.environ.copy()
                result = subprocess.check_call(cmd, env=env)
            except subprocess.CalledProcessError as e:
                retry_count = retry_count + 1
                if retry_count > APT_NO_LOCK_RETRY_COUNT:
                    raise
                result = e.returncode
                log("Couldn't acquire DPKG lock. Will retry in {} seconds."
                    .format(APT_NO_LOCK_RETRY_DELAY))
                time.sleep(APT_NO_LOCK_RETRY_DELAY)

    else:
        env = os.environ.copy()
        env.update(cmd_env)
        subprocess.call(cmd, env=env)


def get_upstream_version(package):
    """Determine upstream version based on installed package

    @returns None (if not installed) or the upstream version
    """
    import apt_pkg
    cache = apt_cache()
    try:
        pkg = cache[package]
    except:
        # the package is unknown to the current apt cache.
        return None

    if not pkg.current_ver:
        # package is known, but no version is currently installed.
        return None

    return apt_pkg.upstream_version(pkg.current_ver.ver_str)
