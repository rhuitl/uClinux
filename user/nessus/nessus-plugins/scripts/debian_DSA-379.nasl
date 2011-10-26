# This script was automatically generated from the dsa-379
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Alexander Hvostov, Julien Blache and Aurelien Jarno discovered several
security-related problems in the sane-backends package, which contains
an API library for scanners including a scanning daemon (in the
package libsane) that can be remotely exploited.  These problems allow
a remote attacker to cause a segmentation fault and/or consume arbitrary
amounts of memory.  The attack is successful, even if the attacker\'s
computer isn\'t listed in saned.conf.
You are only vulnerable if you actually run saned e.g. in xinetd or
inetd.  If the entries in the configuration file of xinetd or inetd
respectively are commented out or do not exist, you are safe.
Try "telnet localhost 6566" on the server that may run saned.
If you
get "connection refused" saned is not running and you are safe.
The Common Vulnerabilities and Exposures project identifies the
following problems:



CVE-2003-0773:

saned checks the identity (IP address) of the remote host only
   after the first communication took place (SANE_NET_INIT).  So
   everyone can send that RPC, even if the remote host is not allowed
   to scan (not listed in saned.conf).
saned lacks error checking nearly everywhere in the code. So
   connection drops are detected very late. If the drop of the
   connection isn\'t detected, the access to the internal wire buffer
   leaves the limits of the allocated memory. So random memory "after"
   the wire buffer is read which will be followed by a segmentation
   fault.
If saned expects strings, it mallocs the memory necessary to store
   the complete string after it receives the size of the string. If
   the connection was dropped before transmitting the size, malloc
   will reserve an arbitrary size of memory. Depending on that size
   and the amount of memory available either malloc fails (->saned
   quits nicely) or a huge amount of memory is allocated. Swapping
   and OOM measures may occur depending on the kernel.
saned doesn\'t check the validity of the RPC numbers it gets before
   getting the parameters.
If debug messages are enabled and a connection is dropped,
   non-null-terminated strings may be printed and segmentation faults
   may occur.
It\'s possible to allocate an arbitrary amount of memory on the
   server running saned even if the connection isn\'t dropped.  At the
   moment this cannot easily be fixed according to the author.
   Better limit the total amount of memory saned may use (ulimit).
For the stable distribution (woody) this problem has been
fixed in version 1.0.7-4.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.11-1 and later.
We recommend that you upgrade your libsane packages.


Solution : http://www.debian.org/security/2003/dsa-379
Risk factor : High';

if (description) {
 script_id(15216);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "379");
 script_cve_id("CVE-2003-0773", "CVE-2003-0774", "CVE-2003-0775", "CVE-2003-0776", "CVE-2003-0777", "CVE-2003-0778");
 script_bugtraq_id(8593, 8594, 8595, 8596, 8597, 8600);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA379] DSA-379-1 sane-backends");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-379-1 sane-backends");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libsane', release: '3.0', reference: '1.0.7-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsane is vulnerable in Debian 3.0.\nUpgrade to libsane_1.0.7-4\n');
}
if (deb_check(prefix: 'libsane-dev', release: '3.0', reference: '1.0.7-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsane-dev is vulnerable in Debian 3.0.\nUpgrade to libsane-dev_1.0.7-4\n');
}
if (deb_check(prefix: 'sane-backends', release: '3.1', reference: '1.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sane-backends is vulnerable in Debian 3.1.\nUpgrade to sane-backends_1.0\n');
}
if (deb_check(prefix: 'sane-backends', release: '3.0', reference: '1.0.7-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sane-backends is vulnerable in Debian woody.\nUpgrade to sane-backends_1.0.7-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
