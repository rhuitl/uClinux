# This script was automatically generated from the dsa-341
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
liece, an IRC client for Emacs, does not take appropriate security
precautions when creating temporary files.  This bug could potentially
be exploited to overwrite arbitrary files with the privileges of the
user running Emacs and liece, potentially with contents supplied
by the attacker.
For the stable distribution (woody) this problem has been fixed in
version 2.0+0.20020217cvs-2.1.
For the unstable distribution (sid) this problem has been fixed in
version 2.0+0.20030527cvs-1.
We recommend that you update your liece package.


Solution : http://www.debian.org/security/2003/dsa-341
Risk factor : High';

if (description) {
 script_id(15178);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "341");
 script_cve_id("CVE-2003-0537");
 script_bugtraq_id(8124);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA341] DSA-341-1 liece");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-341-1 liece");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'liece', release: '3.0', reference: '2.0+0.20020217cvs-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package liece is vulnerable in Debian 3.0.\nUpgrade to liece_2.0+0.20020217cvs-2.1\n');
}
if (deb_check(prefix: 'liece-dcc', release: '3.0', reference: '2.0+0.20020217cvs-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package liece-dcc is vulnerable in Debian 3.0.\nUpgrade to liece-dcc_2.0+0.20020217cvs-2.1\n');
}
if (deb_check(prefix: 'liece', release: '3.1', reference: '2.0+0.20030527cvs-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package liece is vulnerable in Debian 3.1.\nUpgrade to liece_2.0+0.20030527cvs-1\n');
}
if (deb_check(prefix: 'liece', release: '3.0', reference: '2.0+0.20020217cvs-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package liece is vulnerable in Debian woody.\nUpgrade to liece_2.0+0.20020217cvs-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
