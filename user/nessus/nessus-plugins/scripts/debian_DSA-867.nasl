# This script was automatically generated from the dsa-867
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Eduard Bloch discovered that a rule file in module-assistant, a tool
to ease the creation of module packages, creates a temporary file in
an insecure fashion.  It is usually executed from other packages as
well.
The old stable distribution (woody) does not contain a module-assistant
package.
For the stable distribution (sarge) this problem has been fixed in
version 0.9sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.10.
We recommend that you upgrade your module-assistant package.


Solution : http://www.debian.org/security/2005/dsa-867
Risk factor : High';

if (description) {
 script_id(20070);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "867");
 script_cve_id("CVE-2005-3121");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA867] DSA-867-1 module-assistant");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-867-1 module-assistant");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'module-assistant', release: '', reference: '0.9.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package module-assistant is vulnerable in Debian .\nUpgrade to module-assistant_0.9.10\n');
}
if (deb_check(prefix: 'module-assistant', release: '3.1', reference: '0.9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package module-assistant is vulnerable in Debian 3.1.\nUpgrade to module-assistant_0.9sarge1\n');
}
if (deb_check(prefix: 'module-assistant', release: '3.1', reference: '0.9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package module-assistant is vulnerable in Debian sarge.\nUpgrade to module-assistant_0.9sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
