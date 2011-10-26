# This script was automatically generated from the dsa-126
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '

A cross-site scripting (CSS) problem was discovered in Horde and IMP (a web
based IMAP mail package). This was fixed upstream in Horde version 1.2.8
and IMP version 2.2.8. The relevant patches have been back-ported to 
version 1.2.6-0.potato.5 of the horde package and version 2.2.6-0.potato.5
of the imp package.
This release also fixes a bug introduced by the PHP security fix from 
DSA-115-1: Postgres support for PHP was changed
in a subtle way which broke the Postgres support from IMP.


Solution : http://www.debian.org/security/2002/dsa-126
Risk factor : High';

if (description) {
 script_id(14963);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "126");
 script_cve_id("CVE-2002-0181");
 script_bugtraq_id(4444);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA126] DSA-126-1 imp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-126-1 imp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'horde', release: '2.2', reference: '1.2.6-0.potato.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package horde is vulnerable in Debian 2.2.\nUpgrade to horde_1.2.6-0.potato.5\n');
}
if (deb_check(prefix: 'imp', release: '2.2', reference: '2.2.6-0.potato.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imp is vulnerable in Debian 2.2.\nUpgrade to imp_2.2.6-0.potato.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
