#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12613);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0370");
 name["english"] = "FreeBSD : SA-04:06.ipv6 : setsockopt()";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of FreeBSD 5.2 older than FreeBSD 5.2.1-p4

There is a programming error in the version of this kernel which may allow
a local attacker to read portions of the kernel memory or to cause a system
panic by misusing the setsockopt() system call on IPv6 sockets.

Solution : http://www.vuxml.org/freebsd/2c6acefd-8194-11d8-9645-0020ed76ef5a.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the FreeBSD kernel";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}



include("freebsd_package.inc");

package = get_kb_item("Host/FreeBSD/release");
if ( egrep(pattern:"FreeBSD-5\.2", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.2.1_4") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

