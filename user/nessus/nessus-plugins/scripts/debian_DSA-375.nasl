# This script was automatically generated from the dsa-375
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Morgan alias SM6TKY discovered and fixed several security related
problems in LinuxNode, an Amateur Packet Radio Node program.  The
buffer overflow he discovered can be used to gain unauthorised root
access and can be remotely triggered.
For the stable distribution (woody) this problem has been
fixed in version 0.3.0a-2woody1.
For the unstable distribution (sid) this problem has been fixed in
version 0.3.2-1.
We recommend that you upgrade your node packages immediately.


Solution : http://www.debian.org/security/2003/dsa-375
Risk factor : High';

if (description) {
 script_id(15212);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "375");
 script_cve_id("CVE-2003-0707", "CVE-2003-0708");
 script_bugtraq_id(8512);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA375] DSA-375-1 node");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-375-1 node");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'node', release: '3.0', reference: '0.3.0a-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package node is vulnerable in Debian 3.0.\nUpgrade to node_0.3.0a-2woody1\n');
}
if (deb_check(prefix: 'node', release: '3.1', reference: '0.3.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package node is vulnerable in Debian 3.1.\nUpgrade to node_0.3.2-1\n');
}
if (deb_check(prefix: 'node', release: '3.0', reference: '0.3.0a-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package node is vulnerable in Debian woody.\nUpgrade to node_0.3.0a-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
