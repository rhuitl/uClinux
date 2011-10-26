# This script was automatically generated from the dsa-634
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Patrice Fournier discovered a vulnerability in the authorisation
subsystem of hylafax, a flexible client/server fax system.  A local or
remote user guessing the contents of the hosts.hfaxd database could
gain unauthorised access to the fax system.
Some installations of hylafax may actually utilise the weak hostname
and username validation for authorized uses.  For example, hosts.hfaxd
entries that may be common are

  192.168.0
  username:uid:pass:adminpass
  user@host


After updating, these entries will need to be modified in order to
continue to function.  Respectively, the correct entries should be

  192.168.0.[0-9]+
  username@:uid:pass:adminpass
  user@host


Unless such matching of "username" with "otherusername" and "host" with
"hostname" is desired, the proper form of these entries should include
the delimiter and markers like this

  @192.168.0.[0-9]+$
  ^username@:uid:pass:adminpass
  ^user@host$


For the stable distribution (woody) this problem has been fixed in
version 4.1.1-3.1.
For the unstable distribution (sid) this problem has been fixed in
version 4.2.1-1.
We recommend that you upgrade your hylafax packages.


Solution : http://www.debian.org/security/2005/dsa-634
Risk factor : High';

if (description) {
 script_id(16131);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "634");
 script_cve_id("CVE-2004-1182");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA634] DSA-634-1 hylafax");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-634-1 hylafax");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hylafax-client', release: '3.0', reference: '4.1.1-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-client is vulnerable in Debian 3.0.\nUpgrade to hylafax-client_4.1.1-3.1\n');
}
if (deb_check(prefix: 'hylafax-doc', release: '3.0', reference: '4.1.1-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-doc is vulnerable in Debian 3.0.\nUpgrade to hylafax-doc_4.1.1-3.1\n');
}
if (deb_check(prefix: 'hylafax-server', release: '3.0', reference: '4.1.1-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax-server is vulnerable in Debian 3.0.\nUpgrade to hylafax-server_4.1.1-3.1\n');
}
if (deb_check(prefix: 'hylafax', release: '3.1', reference: '4.2.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax is vulnerable in Debian 3.1.\nUpgrade to hylafax_4.2.1-1\n');
}
if (deb_check(prefix: 'hylafax', release: '3.0', reference: '4.1.1-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hylafax is vulnerable in Debian woody.\nUpgrade to hylafax_4.1.1-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
