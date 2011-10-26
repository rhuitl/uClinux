# This script was automatically generated from the dsa-230
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities have been discovered in Bugzilla, a web-based bug
tracking system, by its authors.  The Common Vulnerabilities and
Exposures Project identifies the following vulnerabilities:
  
   The provided data collection
   script intended to be run as a nightly cron job changes the
   permissions of the data/mining directory to be world-writable every
   time it runs.  This would enable local users to alter or delete the
   collected data.
  
  
   The default .htaccess scripts
   provided by checksetup.pl do not block access to backups of the
   localconfig file that might be created by editors such as vi or
   emacs (typically these will have a .swp or ~ suffix).  This allows
   an end user to download one of the backup copies and potentially
   obtain your database password.
  
  
   This does not affect the Debian installation because there is no
   .htaccess as all data file aren\'t under the CGI path as they are on
   the standard Bugzilla package.  Additionally, the configuration is
   in /etc/bugzilla/localconfig and hence outside of the web directory.
For the current stable distribution (woody) these problems have been
fixed in version 2.14.2-0woody4.
The old stable distribution (potato) does not contain a Bugzilla
package.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your bugzilla packages.


Solution : http://www.debian.org/security/2003/dsa-230
Risk factor : High';

if (description) {
 script_id(15067);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "230");
 script_cve_id("CVE-2003-0012", "CVE-2003-0013");
 script_bugtraq_id(6501, 6502);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA230] DSA-230-1 bugzilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-230-1 bugzilla");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bugzilla', release: '3.0', reference: '2.14.2-0woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bugzilla is vulnerable in Debian 3.0.\nUpgrade to bugzilla_2.14.2-0woody4\n');
}
if (deb_check(prefix: 'bugzilla-doc', release: '3.0', reference: '2.14.2-0woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bugzilla-doc is vulnerable in Debian 3.0.\nUpgrade to bugzilla-doc_2.14.2-0woody4\n');
}
if (deb_check(prefix: 'bugzilla', release: '3.0', reference: '2.14.2-0woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bugzilla is vulnerable in Debian woody.\nUpgrade to bugzilla_2.14.2-0woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
