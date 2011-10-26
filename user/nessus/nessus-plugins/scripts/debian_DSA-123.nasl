# This script was automatically generated from the dsa-123
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Janusz Niewiadomski and Wojciech Purczynski reported a buffer overflow
in the address_match of listar (a listserv style mailing-list manager).
This has been fixed in version 0.129a-2.potato1.


Solution : http://www.debian.org/security/2002/dsa-123
Risk factor : High';

if (description) {
 script_id(14960);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "123");
 script_cve_id("CVE-2002-0467");
 script_bugtraq_id(4176);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA123] DSA-123-1 listar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-123-1 listar");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'listar', release: '2.2', reference: '0.129a-2.potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package listar is vulnerable in Debian 2.2.\nUpgrade to listar_0.129a-2.potato1\n');
}
if (deb_check(prefix: 'listar-cgi', release: '2.2', reference: '0.129a-2.potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package listar-cgi is vulnerable in Debian 2.2.\nUpgrade to listar-cgi_0.129a-2.potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
