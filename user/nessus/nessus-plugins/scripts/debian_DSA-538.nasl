# This script was automatically generated from the dsa-538
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The rsync developers have discovered a security related problem in
rsync, a fast remote file copy program, which offers an attacker to
access files outside of the defined directory.  To exploit this
path-sanitizing bug, rsync has to run in daemon mode with the chroot
option being disabled.  It does not affect the normal send/receive
filenames that specify what files should be transferred.  It does
affect certain option paths that cause auxiliary files to be read or
written.
For the stable distribution (woody) this problem has been fixed in
version 2.5.5-0.6.
For the unstable distribution (sid) this problem has been fixed in
version 2.6.2-3.
We recommend that you upgrade your rsync package.


Solution : http://www.debian.org/security/2004/dsa-538
Risk factor : High';

if (description) {
 script_id(15375);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "538");
 script_cve_id("CVE-2004-0792");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA538] DSA-538-1 rsync");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-538-1 rsync");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'rsync', release: '3.0', reference: '2.5.5-0.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rsync is vulnerable in Debian 3.0.\nUpgrade to rsync_2.5.5-0.6\n');
}
if (deb_check(prefix: 'rsync', release: '3.1', reference: '2.6.2-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rsync is vulnerable in Debian 3.1.\nUpgrade to rsync_2.6.2-3\n');
}
if (deb_check(prefix: 'rsync', release: '3.0', reference: '2.5.5-0.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rsync is vulnerable in Debian woody.\nUpgrade to rsync_2.5.5-0.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
