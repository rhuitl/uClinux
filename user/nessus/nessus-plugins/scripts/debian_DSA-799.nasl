# This script was automatically generated from the dsa-799
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A trivially-exploitable bug was discovered in webcalendar that
allows an attacker to execute arbitrary code with the privileges of
the HTTP daemon on a system running a vulnerable version.
The old stable distribution (woody) does not contain the webcalendar
package.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.45-4sarge2.
For the unstable distribution (sid) this problem will be fixed
shortly.
We recommend that you upgrade your webcalendar package immediately.


Solution : http://www.debian.org/security/2005/dsa-799
Risk factor : High';

if (description) {
 script_id(19569);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "799");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA799] DSA-799-1 webcalendar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-799-1 webcalendar");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webcalendar is vulnerable in Debian 3.1.\nUpgrade to webcalendar_0.9.45-4sarge2\n');
}
if (deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webcalendar is vulnerable in Debian sarge.\nUpgrade to webcalendar_0.9.45-4sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
