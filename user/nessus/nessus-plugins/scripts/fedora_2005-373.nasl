#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18337);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1389", "CVE-2005-1390", "CVE-2005-1519", "CVE-1999-0710");
 
 name["english"] = "Fedora Core 3 2005-373: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-373 (squid).

Squid is a high-performance proxy caching server for Web clients,
supporting FTP, gopher, and HTTP data objects. Unlike traditional
caching software, Squid handles all requests in a single,
non-blocking, I/O-driven process. Squid keeps meta data and especially
hot objects cached in RAM, caches DNS lookups, supports non-blocking
DNS lookups, and implements negative caching of failed requests.

Squid consists of a main server program squid, a Domain Name System
lookup program (dnsserver), a program for retrieving FTP data
(ftpget), and some management and client tools.


* Mon May 16 2005 Jay Fenlason 7:2.5.STABLE9-1.FC3.6

- More upstream patches, including ones for
bz#157456 CVE-2005-1519 DNS lookups unreliable on untrusted networks
bz#156162 CVE-1999-0710 cachemgr.cgi access control bypass

- The following bugs had already been fixed, but the announcements
were lost
bz#156711 CVE-2005-1390 HTTP Request Smuggling Vulnerabilities
bz#156703 CVE-2005-1389 HTTP Response Splitting Vulnerabilities
(Both fixed by squid-7:2.5.STABLE8-1.FC3.1)
bz#151419 Unexpected access control results on configuration errors
(Fixed by 7:2.5.STABLE9-1.FC3.2)
bz#152647#squid-2.5.STABLE9-1.FC3.4.x86_64.rpm is broken
(fixed by 7:2.5.STABLE9-1.FC3.5)
bz#141938 squid ldap authentification broken
(Fixed by 7:2.5.STABLE7-1.FC3)

* Fri Apr 1 2005 Jay Fenlason 7:2.5.STABLE9-1.FC3.5

- More upstream patches, including a new version of the -2GB patch
that doesn't break diskd.



Solution : http://www.fedoranews.org/blog/index.php?p=681
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"squid-2.5.STABLE9-1.FC3.6", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-debuginfo-2.5.STABLE9-1.FC3.6", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"squid-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-1389", value:TRUE);
 set_kb_item(name:"CVE-2005-1390", value:TRUE);
 set_kb_item(name:"CVE-2005-1519", value:TRUE);
 set_kb_item(name:"CVE-1999-0710", value:TRUE);
}
