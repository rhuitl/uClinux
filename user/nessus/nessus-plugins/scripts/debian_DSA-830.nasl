# This script was automatically generated from the dsa-830
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Drew Parsons noticed that the post-installation script of ntlmaps, an
NTLM authorisation proxy server, changes the permissions of the
configuration file to be world-readable.  It contains the user name
and password of the Windows NT system that ntlmaps connects to and,
hence, leaks them to local users.
The old stable distribution (woody) does not contain an ntlmaps package.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.9-2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.9-4.
We recommend that you upgrade your ntlmaps package.


Solution : http://www.debian.org/security/2005/dsa-830
Risk factor : High';

if (description) {
 script_id(19799);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "830");
 script_cve_id("CVE-2005-2962");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA830] DSA-830-1 ntlmaps");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-830-1 ntlmaps");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ntlmaps', release: '', reference: '0.9.9-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntlmaps is vulnerable in Debian .\nUpgrade to ntlmaps_0.9.9-4\n');
}
if (deb_check(prefix: 'ntlmaps', release: '3.1', reference: '0.9.9-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntlmaps is vulnerable in Debian 3.1.\nUpgrade to ntlmaps_0.9.9-2sarge1\n');
}
if (deb_check(prefix: 'ntlmaps', release: '3.1', reference: '0.9.9-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntlmaps is vulnerable in Debian sarge.\nUpgrade to ntlmaps_0.9.9-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
