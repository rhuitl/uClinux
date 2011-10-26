# This script was automatically generated from the dsa-499
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in rsync, a file transfer program,
whereby a remote user could cause an rsync daemon to write files
outside of the intended directory tree.  This vulnerability is not
exploitable when the daemon is configured with the \'chroot\' option.
For the current stable distribution (woody) this problem has been
fixed in version 2.5.5-0.5.
For the unstable distribution (sid), this problem has been fixed in
version 2.6.1-1.
We recommend that you update your rsync package.


Solution : http://www.debian.org/security/2004/dsa-499
Risk factor : High';

if (description) {
 script_id(15336);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "499");
 script_cve_id("CVE-2004-0426");
 script_bugtraq_id(10247);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA499] DSA-499-2 rsync");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-499-2 rsync");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'rsync', release: '3.0', reference: '2.5.5-0.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rsync is vulnerable in Debian 3.0.\nUpgrade to rsync_2.5.5-0.5\n');
}
if (deb_check(prefix: 'rsync', release: '3.1', reference: '2.6.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rsync is vulnerable in Debian 3.1.\nUpgrade to rsync_2.6.1-1\n');
}
if (deb_check(prefix: 'rsync', release: '3.0', reference: '2.5.5-0.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rsync is vulnerable in Debian woody.\nUpgrade to rsync_2.5.5-0.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
