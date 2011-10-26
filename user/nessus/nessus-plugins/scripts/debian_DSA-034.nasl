# This script was automatically generated from the dsa-034
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Fumitoshi Ukai and Denis Barbier have found several
potential buffer overflow bugs in our version of ePerl as distributed in all of
our distributions.  

When eperl is installed setuid root, it can switch to the UID/GID of
the scripts owner.  Although Debian doesn\'t ship the program setuid
root, this is a useful feature which people may have activated
locally.  When the program is used as /usr/lib/cgi-bin/nph-eperl the
bugs could lead into a remote vulnerability as well.

Version 2.2.14-0.7potato2 fixes this; we recommend you upgrade your eperl
package immediately.  


Solution : http://www.debian.org/security/2001/dsa-034
Risk factor : High';

if (description) {
 script_id(14871);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "034");
 script_cve_id("CVE-2001-0458");
 script_bugtraq_id(2464);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA034] DSA-034-1 ePerl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-034-1 ePerl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'eperl', release: '2.2', reference: '2.2.14-0.7potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eperl is vulnerable in Debian 2.2.\nUpgrade to eperl_2.2.14-0.7potato2\n');
}
if (w) { security_hole(port: 0, data: desc); }
