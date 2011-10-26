#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13718);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0541");
 
 name["english"] = "Fedora Core 2 2004-164: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-164 (squid).

Squid is a high-performance proxy caching server for Web clients,
supporting FTP, gopher, and HTTP data objects. Unlike traditional
caching software, Squid handles all requests in a single,
non-blocking, I/O-driven process. Squid keeps meta data and especially
hot objects cached in RAM, caches DNS lookups, supports non-blocking
DNS lookups, and implements negative caching of failed requests.

Squid consists of a main server program squid, a Domain Name System
lookup program (dnsserver), a program for retrieving FTP data
(ftpget), and some management and client tools.


* Mon Jun 07 2004 Jay Fenlason <fenlason@redhat.com> 7:2.5.STABLE3-4.fc2

- Backport security fix for ntlm auth helper (CVE-2004-0541).

* Thu Apr 08 2004 Jay Fenlason <fenlason@redhat.com> 7:2.5.STABLE5-3

- Fix the -pipe patch to have the correct name of the winbind pipe.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-164.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"squid-2.5.STABLE5-4.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-debuginfo-2.5.STABLE5-4.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"squid-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0541", value:TRUE);
}
