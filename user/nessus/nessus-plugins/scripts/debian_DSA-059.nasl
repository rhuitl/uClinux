# This script was automatically generated from the dsa-059
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Luki R. reported a bug in man-db: it did not handle nested calls of
drop_effective_privs() and regain_effective_privs() correctly which
would cause it to regain privileges too early. This could be abused
to make man create files as user man.

This has been fixed in version 2.3.16-4, and we recommend that you 
upgrade your man-db package immediately. If you use suidmanager you 
can also use that to make sure man and mandb are not installed suid
which protects you from this problem. This can be done with the
following commands:


   suidregister /usr/lib/man-db/man root root 0755
   suidregister /usr/lib/man-db/mandb root root 0755


    
Of course even when using suidmanager an upgrade is still strongly 
recommended.



Solution : http://www.debian.org/security/2001/dsa-059
Risk factor : High';

if (description) {
 script_id(14896);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "059");
 script_cve_id("CVE-2001-1331");
 script_bugtraq_id(2720, 2815);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA059] DSA-059-1 man-db");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-059-1 man-db");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'man-db', release: '2.2', reference: '2.3.16-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package man-db is vulnerable in Debian 2.2.\nUpgrade to man-db_2.3.16-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
