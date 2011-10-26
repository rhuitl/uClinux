# This script was automatically generated from the dsa-643
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"jaguar" of the Debian Security Audit Project has discovered several
buffer overflows in queue, a transparent load balancing system.
For the stable distribution (woody) these problems have been fixed in
version 1.30.1-4woody2.
For the unstable distribution (sid) these problems have been fixed in
version 1.30.1-5.
We recommend that you upgrade your queue package.


Solution : http://www.debian.org/security/2005/dsa-643
Risk factor : High';

if (description) {
 script_id(16196);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "643");
 script_cve_id("CVE-2004-0555");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA643] DSA-643-1 queue");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-643-1 queue");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'queue', release: '3.0', reference: '1.30.1-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package queue is vulnerable in Debian 3.0.\nUpgrade to queue_1.30.1-4woody2\n');
}
if (deb_check(prefix: 'queue', release: '3.1', reference: '1.30.1-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package queue is vulnerable in Debian 3.1.\nUpgrade to queue_1.30.1-5\n');
}
if (deb_check(prefix: 'queue', release: '3.0', reference: '1.30.1-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package queue is vulnerable in Debian woody.\nUpgrade to queue_1.30.1-4woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
