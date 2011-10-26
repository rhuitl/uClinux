# This script was automatically generated from the dsa-956
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Pfetzing discovered that lshd, a Secure Shell v2 (SSH2)
protocol server, leaks a couple of file descriptors, related to the
randomness generator, to user shells which are started by lshd.  A
local attacker can truncate the server\'s seed file, which may prevent
the server from starting, and with some more effort, maybe also crack
session keys.
After applying this update, you should remove the server\'s seed file
(/var/spool/lsh/yarrow-seed-file) and then regenerate it with
"lsh-make-seed --server" as root.
For security reasons, lsh-make-seed really needs to be run from the
console of the system you are running it on.  If you run lsh-make-seed
using a remote shell, the timing information lsh-make-seed uses for
its random seed creation is likely to be screwed.  If need be, you can
generate the random seed on a different system than that which it will
eventually be on, by installing the lsh-utils package and running
"lsh-make-seed -o my-other-server-seed-file".  You may then transfer
the seed to the destination system as using a secure connection.
The old stable distribution (woody) may not be affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.1-3sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.1cdbs-4.
We recommend that you upgrade your lsh-server package.


Solution : http://www.debian.org/security/2006/dsa-956
Risk factor : High';

if (description) {
 script_id(22822);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "956");
 script_cve_id("CVE-2006-0353");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA956] DSA-956-1 lsh-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-956-1 lsh-server");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lsh-utils', release: '', reference: '2.0.1cdbs-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-utils is vulnerable in Debian .\nUpgrade to lsh-utils_2.0.1cdbs-4\n');
}
if (deb_check(prefix: 'lsh-client', release: '3.1', reference: '2.0.1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-client is vulnerable in Debian 3.1.\nUpgrade to lsh-client_2.0.1-3sarge1\n');
}
if (deb_check(prefix: 'lsh-server', release: '3.1', reference: '2.0.1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-server is vulnerable in Debian 3.1.\nUpgrade to lsh-server_2.0.1-3sarge1\n');
}
if (deb_check(prefix: 'lsh-utils', release: '3.1', reference: '2.0.1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-utils is vulnerable in Debian 3.1.\nUpgrade to lsh-utils_2.0.1-3sarge1\n');
}
if (deb_check(prefix: 'lsh-utils-doc', release: '3.1', reference: '2.0.1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-utils-doc is vulnerable in Debian 3.1.\nUpgrade to lsh-utils-doc_2.0.1-3sarge1\n');
}
if (deb_check(prefix: 'lsh-utils', release: '3.1', reference: '2.0.1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lsh-utils is vulnerable in Debian sarge.\nUpgrade to lsh-utils_2.0.1-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
