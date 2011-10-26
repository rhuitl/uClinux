# This script was automatically generated from the dsa-066
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steven van Acker reported on bugtraq that the version of cfingerd (a
configurable finger daemon) as distributed in Debian GNU/Linux 2.2
suffers from two problems:


The code that reads configuration files (files in which $ commands are
   expanded) copied its input to a buffer without checking for a buffer
   overflow. When the ALLOW_LINE_PARSING feature is enabled that code
   is used for reading users\' files as well, so local users could exploit
   this.

There also was a printf call in the same routine that did not protect
   against printf format attacks.


Since ALLOW_LINE_PARSING is enabled in the default /etc/cfingerd.conf
local users could use this to gain root access.

This has been fixed in version 1.4.1-1.2, and we recommend that you upgrade
your cfingerd package immediately.



Solution : http://www.debian.org/security/2001/dsa-066
Risk factor : High';

if (description) {
 script_id(14903);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "066");
 script_cve_id("CVE-2001-0735");
 script_bugtraq_id(2914, 2915);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA066] DSA-066-1 cfingerd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-066-1 cfingerd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cfingerd', release: '2.2', reference: '1.4.1-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfingerd is vulnerable in Debian 2.2.\nUpgrade to cfingerd_1.4.1-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
