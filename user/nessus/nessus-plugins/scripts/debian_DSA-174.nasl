# This script was automatically generated from the dsa-174
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Nathan Wallwork discovered a buffer overflow in heartbeat, a subsystem
for High-Availability Linux.  A remote attacker could send a specially
crafted UDP packet that overflows a buffer, leaving heartbeat to
execute arbitrary code as root.
This problem has been fixed in version 0.4.9.0l-7.2 for the current
stable distribution (woody) and version 0.4.9.2-1 for the unstable
distribution (sid).  The old stable distribution (potato) doesn\'t
contain a heartbeat package.
We recommend that you upgrade your heartbeat package immediately if
you run internet connected servers that are heartbeat-monitored.


Solution : http://www.debian.org/security/2002/dsa-174
Risk factor : High';

if (description) {
 script_id(15011);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "174");
 script_cve_id("CVE-2002-1215");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA174] DSA-174-1 heartbeat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-174-1 heartbeat");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'heartbeat', release: '3.0', reference: '0.4.9.0l-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heartbeat is vulnerable in Debian 3.0.\nUpgrade to heartbeat_0.4.9.0l-7.2\n');
}
if (deb_check(prefix: 'ldirectord', release: '3.0', reference: '0.4.9.0l-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ldirectord is vulnerable in Debian 3.0.\nUpgrade to ldirectord_0.4.9.0l-7.2\n');
}
if (deb_check(prefix: 'libstonith-dev', release: '3.0', reference: '0.4.9.0l-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libstonith-dev is vulnerable in Debian 3.0.\nUpgrade to libstonith-dev_0.4.9.0l-7.2\n');
}
if (deb_check(prefix: 'libstonith0', release: '3.0', reference: '0.4.9.0l-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libstonith0 is vulnerable in Debian 3.0.\nUpgrade to libstonith0_0.4.9.0l-7.2\n');
}
if (deb_check(prefix: 'stonith', release: '3.0', reference: '0.4.9.0l-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package stonith is vulnerable in Debian 3.0.\nUpgrade to stonith_0.4.9.0l-7.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
