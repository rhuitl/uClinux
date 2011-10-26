# This script was automatically generated from the dsa-378
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Nicolas Boullis discovered two vulnerabilities in mah-jong, a
network-enabled game.
This vulnerability could be exploited by a remote attacker to
   execute arbitrary code with the privileges of the user running the
   mah-jong server.
This vulnerability could be exploited by a remote attacker to cause
  the mah-jong server to enter a tight loop and stop responding to
  commands.
For the stable distribution (woody) these problems have been fixed in
version 1.4-2.
For the unstable distribution (sid) these problems have been fixed in
version 1.5.6-2.
We recommend that you update your mah-jong package.


Solution : http://www.debian.org/security/2003/dsa-378
Risk factor : High';

if (description) {
 script_id(15215);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "378");
 script_cve_id("CVE-2003-0705", "CVE-2003-0706");
 script_bugtraq_id(8557, 8558);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA378] DSA-378-1 mah-jong");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-378-1 mah-jong");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mah-jong', release: '3.0', reference: '1.4-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mah-jong is vulnerable in Debian 3.0.\nUpgrade to mah-jong_1.4-2\n');
}
if (deb_check(prefix: 'mah-jong', release: '3.1', reference: '1.5.6-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mah-jong is vulnerable in Debian 3.1.\nUpgrade to mah-jong_1.5.6-2\n');
}
if (deb_check(prefix: 'mah-jong', release: '3.0', reference: '1.4-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mah-jong is vulnerable in Debian woody.\nUpgrade to mah-jong_1.4-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
