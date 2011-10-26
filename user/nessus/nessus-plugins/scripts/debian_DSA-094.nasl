# This script was automatically generated from the dsa-094
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Barry A. Warsaw reported several cross-site scripting security holes
in Mailman, due to non-existent escaping of CGI variables. 

These have been fixed upstream in version 2.0.8, and the relevant
patches have been backported to version 1.1-10 in Debian.



Solution : http://www.debian.org/security/2001/dsa-094
Risk factor : High';

if (description) {
 script_id(14931);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "094");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA094] DSA-094-1 mailman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-094-1 mailman");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mailman', release: '2.2', reference: '1.1-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian 2.2.\nUpgrade to mailman_1.1-10\n');
}
if (w) { security_hole(port: 0, data: desc); }
