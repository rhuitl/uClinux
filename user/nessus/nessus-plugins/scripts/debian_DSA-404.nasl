# This script was automatically generated from the dsa-404
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The rsync team has received evidence that a vulnerability in all
versions of rsync prior to 2.5.7, a fast remote file copy program, was
recently used in combination with a Linux kernel vulnerability to
compromise the security of a public rsync server.
While this heap overflow vulnerability could not be used by itself to
obtain root access on an rsync server, it could be used in combination
with the recently announced do_brk() vulnerability in the Linux kernel
to produce a full remote compromise.
Please note that this vulnerability only affects the use of rsync as
an "rsync server".  To see if you are running a rsync server you
should use the command "netstat -a -n" to see if you are listening on
TCP port 873.  If you are not listening on TCP port 873 then you are
not running an rsync server.
For the stable distribution (woody) this problem has been fixed in
version 2.5.5-0.2.
For the unstable distribution (sid) this problem has been fixed in
version 2.5.6-1.1.
However, since the Debian infrastructure is not yet fully functional
after the recent break-in, packages for the unstable distribution are
not able to enter the archive for a while.  Hence they were placed in
Joey\'s home directory on the security machine.
We recommend that you upgrade your rsync package immediately if you
are providing remote sync services.  If you are running testing and
provide remote sync services please use the packages for woody.


Solution : http://www.debian.org/security/2003/dsa-404
Risk factor : High';

if (description) {
 script_id(15241);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0024");
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "404");
 script_cve_id("CVE-2003-0962");
 script_bugtraq_id(9153);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA404] DSA-404-1 rsync");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-404-1 rsync");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'rsync', release: '3.0', reference: '2.5.5-0.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rsync is vulnerable in Debian 3.0.\nUpgrade to rsync_2.5.5-0.2\n');
}
if (deb_check(prefix: 'rsync', release: '3.1', reference: '2.5.6-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rsync is vulnerable in Debian 3.1.\nUpgrade to rsync_2.5.6-1.1\n');
}
if (deb_check(prefix: 'rsync', release: '3.0', reference: '2.5.5-0.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rsync is vulnerable in Debian woody.\nUpgrade to rsync_2.5.5-0.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
