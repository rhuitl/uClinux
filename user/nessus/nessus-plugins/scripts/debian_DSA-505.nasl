# This script was automatically generated from the dsa-505
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Esser discovered a heap overflow in the CVS server, which
serves the popular Concurrent Versions System.  Malformed "Entry"
Lines in combination with Is-modified and Unchanged can be used to
overflow malloc()ed memory.  This was proven to be exploitable.
For the stable distribution (woody) this problem has been fixed in
version 1.11.1p1debian-9woody4.
For the unstable distribution (sid) this problem has been fixed in
version 1.12.5-6.
We recommend that you upgrade your cvs package immediately.


Solution : http://www.debian.org/security/2004/dsa-505
Risk factor : High';

if (description) {
 script_id(15342);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "505");
 script_cve_id("CVE-2004-0396");
 script_bugtraq_id(10384);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA505] DSA-505-1 cvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-505-1 cvs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-9woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian 3.0.\nUpgrade to cvs_1.11.1p1debian-9woody4\n');
}
if (deb_check(prefix: 'cvs', release: '3.1', reference: '1.12.5-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian 3.1.\nUpgrade to cvs_1.12.5-6\n');
}
if (deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-9woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian woody.\nUpgrade to cvs_1.11.1p1debian-9woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
