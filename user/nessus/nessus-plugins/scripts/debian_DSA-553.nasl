# This script was automatically generated from the dsa-553
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A security problem has been discovered in getmail, a POP3 and APOP
mail gatherer and forwarder.  An attacker with a shell account on the
victims host could utilise getmail to overwrite arbitrary files when
it is running as root.
For the stable distribution (woody) this problem has been fixed in
version 2.3.7-2.
For the unstable distribution (sid) this problem has been fixed in
version 3.2.5-1.
We recommend that you upgrade your getmail package.


Solution : http://www.debian.org/security/2004/dsa-553
Risk factor : High';

if (description) {
 script_id(15390);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "553");
 script_cve_id("CVE-2004-0880", "CVE-2004-0881");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA553] DSA-553-1 getmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-553-1 getmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'getmail', release: '3.0', reference: '2.3.7-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package getmail is vulnerable in Debian 3.0.\nUpgrade to getmail_2.3.7-2\n');
}
if (deb_check(prefix: 'getmail', release: '3.1', reference: '3.2.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package getmail is vulnerable in Debian 3.1.\nUpgrade to getmail_3.2.5-1\n');
}
if (deb_check(prefix: 'getmail', release: '3.0', reference: '2.3.7-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package getmail is vulnerable in Debian woody.\nUpgrade to getmail_2.3.7-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
