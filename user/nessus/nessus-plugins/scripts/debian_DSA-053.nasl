# This script was automatically generated from the dsa-053
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The nedit (Nirvana editor) package as shipped in the non-free section
accompanying Debian GNU/Linux 2.2/potato had a bug in its printing code:
when printing text it would create a temporary file with the to be
printed text and pass that on to the print system. The temporary file
was not created safely, which could be exploited by an attacked to make
nedit overwrite arbitrary files.

This has been fixed in version 5.02-7.1.



Solution : http://www.debian.org/security/2001/dsa-053
Risk factor : High';

if (description) {
 script_id(14890);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "053");
 script_cve_id("CVE-2001-0556");
 script_bugtraq_id(2667);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA053] DSA-053-1 nedit");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-053-1 nedit");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nedit', release: '2.2', reference: '5.02-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nedit is vulnerable in Debian 2.2.\nUpgrade to nedit_5.02-7.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
