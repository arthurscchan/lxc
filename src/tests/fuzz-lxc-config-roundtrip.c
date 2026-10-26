/*
 * SPDX-License-Identifier: LGPL-2.1+
 *
 * Fuzz the config serialization (encode) direction of liblxc, which
 * none of the existing config-parsing fuzzers exercise:
 *
 *   parse (fuzzed config file) -> getter matrix -> save_config ->
 *   write_config -> re-parse of the written file
 *
 * Threat model: the container configuration file is untrusted input
 * (written by a less privileged user or shipped inside an untrusted
 * image/template). lxc tools read such files, query single items
 * through the public container API (lxcapi_get_config_item) and write
 * the configuration back out (lxcapi_save_config ->
 * confile.c:write_config over conf->unexpanded_config, maintained by
 * do_append_unexp_config_line()/clear_unexp_config_line() during
 * parsing). Bugs in the getter matrix (including the indexed
 * "lxc.net.<i>.*" forms), in the unexpanded-config bookkeeping or in
 * the serialization produce corrupted or truncated re-written
 * configurations and memory corruption in the API users.
 *
 * The fuzzed input drives the configuration *values*; the key matrix
 * (the full config_jump_table / config_jump_table_net key sets plus
 * indexed network forms) is embedded so every getter is swept on
 * every input instead of only the ones the mutator happens to spell.
 */

#include "config.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "conf.h"
#include "confile.h"
#include "lxctest.h"
#include "utils.h"
#include "lxccontainer.h"

/*
 * All keys from config_jump_table and config_jump_table_net in
 * src/lxc/confile.c, plus the indexed network-item forms handled by
 * get_config_net_*().
 */
static const char *const fuzz_keys[] = {
	"lxc.arch",
	"lxc.apparmor.profile",
	"lxc.apparmor.allow_incomplete",
	"lxc.apparmor.allow_nesting",
	"lxc.apparmor.raw",
	"lxc.autodev.tmpfs.size",
	"lxc.autodev",
	"lxc.cap.drop",
	"lxc.cap.keep",
	"lxc.cgroup2",
	"lxc.cgroup.dir.monitor.pivot",
	"lxc.cgroup.dir.monitor",
	"lxc.cgroup.dir.container.inner",
	"lxc.cgroup.dir.container",
	"lxc.cgroup.dir",
	"lxc.cgroup.relative",
	"lxc.console.buffer.size",
	"lxc.console.logfile",
	"lxc.console.path",
	"lxc.console.rotate",
	"lxc.console.size",
	"lxc.sched.core",
	"lxc.environment.runtime",
	"lxc.environment.hooks",
	"lxc.environment",
	"lxc.ephemeral",
	"lxc.execute.cmd",
	"lxc.group",
	"lxc.hook.autodev",
	"lxc.hook.clone",
	"lxc.hook.destroy",
	"lxc.hook.mount",
	"lxc.hook.post-stop",
	"lxc.hook.pre-mount",
	"lxc.hook.pre-start",
	"lxc.hook.start",
	"lxc.hook.start-host",
	"lxc.hook.stop",
	"lxc.hook.version",
	"lxc.hook",
	"lxc.idmap",
	"lxc.include",
	"lxc.init.cmd",
	"lxc.init.gid",
	"lxc.init.groups",
	"lxc.init.uid",
	"lxc.cap.nonroot",
	"lxc.init.cwd",
	"lxc.keyring.session",
	"lxc.log.file",
	"lxc.log.level",
	"lxc.log.syslog",
	"lxc.monitor.unshare",
	"lxc.monitor.signal.pdeath",
	"lxc.mount.auto",
	"lxc.mount.entry",
	"lxc.mount.fstab",
	"lxc.namespace.clone",
	"lxc.namespace.keep",
	"lxc.namespace.share.",
	"lxc.time.offset.boot",
	"lxc.time.offset.monotonic",
	"lxc.net.",
	"lxc.net",
	"lxc.no_new_privs",
	"lxc.prlimit",
	"lxc.pty.max",
	"lxc.rootfs.managed",
	"lxc.rootfs.mount",
	"lxc.rootfs.options",
	"lxc.rootfs.path",
	"lxc.seccomp.allow_nesting",
	"lxc.seccomp.notify.cookie",
	"lxc.seccomp.notify.proxy",
	"lxc.seccomp.profile",
	"lxc.selinux.context.keyring",
	"lxc.selinux.context",
	"lxc.signal.halt",
	"lxc.signal.reboot",
	"lxc.signal.stop",
	"lxc.start.auto",
	"lxc.start.delay",
	"lxc.start.order",
	"lxc.tty.dir",
	"lxc.tty.max",
	"lxc.uts.name",
	"lxc.sysctl",
	"lxc.proc",
	"lxc.net.flags",
	"lxc.net.hwaddr",
	"lxc.net.ipv4.address",
	"lxc.net.ipv4.gateway",
	"lxc.net.ipv6.address",
	"lxc.net.ipv6.gateway",
	"lxc.net.link",
	"lxc.net.l2proxy",
	"lxc.net.macvlan.mode",
	"lxc.net.ipvlan.mode",
	"lxc.net.ipvlan.isolation",
	"lxc.net.mtu",
	"lxc.net.name",
	"lxc.net.script.down",
	"lxc.net.script.up",
	"lxc.net.type",
	"lxc.net.vlan.id",
	"lxc.net.veth.mode",
	"lxc.net.veth.n_rxqueues",
	"lxc.net.veth.n_txqueues",
	"lxc.net.veth.pair",
	"lxc.net.veth.ipv4.route",
	"lxc.net.veth.ipv6.route",
	"lxc.net.veth.vlan.id",
	"lxc.net.veth.vlan.tagged.id",
	"lxc.net.0.type",
	"lxc.net.0.flags",
	"lxc.net.0.name",
	"lxc.net.0.link",
	"lxc.net.0.hwaddr",
	"lxc.net.0.mtu",
	"lxc.net.0.macvlan.mode",
	"lxc.net.0.ipvlan.mode",
	"lxc.net.0.ipvlan.isolation",
	"lxc.net.0.l2proxy",
	"lxc.net.0.vlan.id",
	"lxc.net.0.veth.pair",
	"lxc.net.0.veth.mode",
	"lxc.net.0.veth.n_rxqueues",
	"lxc.net.0.veth.n_txqueues",
	"lxc.net.0.veth.ipv4.route",
	"lxc.net.0.veth.ipv6.route",
	"lxc.net.0.veth.vlan.id",
	"lxc.net.0.veth.vlan.tagged.id",
	"lxc.net.0.ipv4.address",
	"lxc.net.0.ipv4.gateway",
	"lxc.net.0.ipv6.address",
	"lxc.net.0.ipv6.gateway",
	"lxc.net.0.script.up",
	"lxc.net.0.script.down",
	"lxc.net.1.type",
	"lxc.net.1.flags",
	"lxc.net.1.link",
	"lxc.net.1.hwaddr",
	"lxc.net.1.ipv4.address",
	"lxc.net.1.ipv6.address",
	"lxc.net.1.veth.pair",
	"lxc.net.2.type",
	"lxc.net.9.type",
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char tmpf_in[] = "/tmp/fuzz-lxc-config-roundtrip-in-XXXXXX";
	char tmpf_out[] = "/tmp/fuzz-lxc-config-roundtrip-out-XXXXXX";
	struct lxc_container *c = NULL;
	int fd = -1;

	/*
	 * 100Kb should probably be enough to trigger all the issues
	 * we're interested in without any timeouts
	 */
	if (size > 102400)
		return 0;

	fd = lxc_make_tmpfile(tmpf_in, false);
	lxc_test_assert_abort(fd >= 0);
	lxc_write_nointr(fd, data, size);
	close(fd);

	c = lxc_container_new("FUZZ", NULL);
	lxc_test_assert_abort(c);

	/*
	 * lxc_container_new() leaves lxc_conf NULL until a config is
	 * loaded; initialize it so the parse below has somewhere to go
	 * (mirrors load_config_locked()).
	 */
	if (!c->lxc_conf)
		c->lxc_conf = lxc_conf_init();
	lxc_test_assert_abort(c->lxc_conf);

	/*
	 * Parse the fuzzed configuration into the container. A partial
	 * or failing parse still accumulates lines in
	 * conf->unexpanded_config, which is exactly what save_config()
	 * serializes, so do not gate on the return value.
	 */
	lxc_config_read(tmpf_in, c->lxc_conf, false);

	/* Sweep every getter over the parsed state. */
	for (size_t i = 0; i < sizeof(fuzz_keys) / sizeof(fuzz_keys[0]); i++) {
		__do_free char *val = NULL;
		int len;

		len = c->get_config_item(c, fuzz_keys[i], NULL, 0);
		if (len < 0)
			continue;

		val = (char *)malloc(len + 1);
		lxc_test_assert_abort(val);

		if (c->get_config_item(c, fuzz_keys[i], val, len + 1) != len)
			continue;
	}

	/* Serialize the configuration back out ... */
	if (c->save_config(c, tmpf_out)) {
		struct lxc_conf *re_conf;

		/* ... and re-parse what was just written. */
		re_conf = lxc_conf_init();
		lxc_test_assert_abort(re_conf);
		lxc_config_read(tmpf_out, re_conf, false);
		lxc_conf_free(re_conf);
	}

	lxc_container_put(c);

	(void) unlink(tmpf_in);
	(void) unlink(tmpf_out);

	return 0;
}
