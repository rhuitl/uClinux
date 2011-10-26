# This script was automatically generated from the dsa-509
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a vulnerability in xatitv, one of the programs
in the gatos package, which is used to display video with certain
ATI video cards.
xatitv is installed setuid root in order to gain direct access to the
video hardware.  It normally drops root privileges after successfully
initializing itself.  However, if initialization fails due to a
missing configuration file, root privileges are not dropped, and
xatitv executes the system(3) function to launch its configuration
program without sanitizing user-supplied environment variables.
By exploiting this vulnerability, a local user could gain root
privileges if the configuration file does not exist.  However, a
default configuration file is supplied with the package, and so this
vulnerability is not exploitable unless this file is removed by the
administrator.
For the current stable distribution (woody) this problem has been
fixed in version 0.0.5-6woody1.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your gatos package.


Solution : http://www.debian.org/security/2004/dsa-509
Risk factor : High';

if (description) {
 script_id(15346);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "509");
 script_cve_id("CVE-2004-0395");
 script_bugtraq_id(10437);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA509] DSA-509-1 gatos");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-509-1 gatos");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gatos', release: '3.0', reference: '0.0.5-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gatos is vulnerable in Debian 3.0.\nUpgrade to gatos_0.0.5-6woody1\n');
}
if (deb_check(prefix: 'libgatos-dev', release: '3.0', reference: '0.0.5-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgatos-dev is vulnerable in Debian 3.0.\nUpgrade to libgatos-dev_0.0.5-6woody1\n');
}
if (deb_check(prefix: 'libgatos0', release: '3.0', reference: '0.0.5-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgatos0 is vulnerable in Debian 3.0.\nUpgrade to libgatos0_0.0.5-6woody1\n');
}
if (deb_check(prefix: 'gatos', release: '3.0', reference: '0.0.5-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gatos is vulnerable in Debian woody.\nUpgrade to gatos_0.0.5-6woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
