# This script was automatically generated from the dsa-061
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The version of GnuPG (GNU Privacy Guard, an OpenPGP implementation)
as distributed in Debian GNU/Linux 2.2 suffers from two problems:


fish stiqz reported on bugtraq that there was a printf format
problem in the do_get() function: it printed a prompt which included
the filename that was being decrypted without checking for
possible printf format attacks. This could be exploited by tricking
someone into decrypting a file with a specially crafted filename.

The second bug is related to importing secret keys: when gnupg
imported a secret key it would immediately make the associated
public key fully trusted which changes your web of trust without
asking for a confirmation. To fix this you now need a special
option to import a secret key.


Both problems have been fixed in version 1.0.6-0potato1.



Solution : http://www.debian.org/security/2001/dsa-061
Risk factor : High';

if (description) {
 script_id(14898);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "061");
 script_cve_id("CVE-2001-0522");
 script_bugtraq_id(2797);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA061] DSA-061-1 gnupg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-061-1 gnupg");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnupg', release: '2.2', reference: '1.0.6-0potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg is vulnerable in Debian 2.2.\nUpgrade to gnupg_1.0.6-0potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }
