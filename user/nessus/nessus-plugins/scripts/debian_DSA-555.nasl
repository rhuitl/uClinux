# This script was automatically generated from the dsa-555
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Simon Josefsson noticed that the tspc.conf configuration file in
freenet6, a client to configure an IPv6 tunnel to freenet6.net, is set
world readable.  This file can contain the username and the password
used to contact the IPv6 tunnelbroker freenet6.net.
For the stable distribution (woody) this problem has been fixed in
version 0.9.6-1woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1.0-2.2.
We recommend that you upgrade your freenet6 package.


Solution : http://www.debian.org/security/2004/dsa-555
Risk factor : High';

if (description) {
 script_id(15653);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "555");
 script_cve_id("CVE-2004-0563");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA555] DSA-555-1 freenet6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-555-1 freenet6");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'freenet6', release: '3.0', reference: '0.9.6-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freenet6 is vulnerable in Debian 3.0.\nUpgrade to freenet6_0.9.6-1woody2\n');
}
if (deb_check(prefix: 'freenet6', release: '3.1', reference: '1.0-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freenet6 is vulnerable in Debian 3.1.\nUpgrade to freenet6_1.0-2.2\n');
}
if (deb_check(prefix: 'freenet6', release: '3.0', reference: '0.9.6-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freenet6 is vulnerable in Debian woody.\nUpgrade to freenet6_0.9.6-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
