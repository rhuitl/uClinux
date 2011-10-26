# This script was automatically generated from the dsa-106
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Sebastian Krahmer found several places in rsync (a popular tool to synchronise files between machines)
where signed and unsigned numbers
were mixed which resulted in insecure code (see <a
href="http://online.securityfocus.com/bid/3958">securityfocus.com</a>).
This could be abused by
remote users to write 0-bytes in rsync\'s memory and trick rsync into
executing arbitrary code.

This has been fixed in version 2.3.2-1.3 and we recommend you upgrade
your rsync package immediately.
Unfortunately the patch used to fix that problem broke rsync.
This has been fixed in version 2.3.2-1.5 and we recommend you
upgrade to that version immediately.


Solution : http://www.debian.org/security/2002/dsa-106
Risk factor : High';

if (description) {
 script_id(14943);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "106");
 script_cve_id("CVE-2002-0048");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA106] DSA-106-2 rsync");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-106-2 rsync");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'rsync', release: '2.2', reference: '2.3.2-1.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rsync is vulnerable in Debian 2.2.\nUpgrade to rsync_2.3.2-1.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
