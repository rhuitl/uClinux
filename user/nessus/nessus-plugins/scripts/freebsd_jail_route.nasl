#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12555);
 script_bugtraq_id(10485);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0125");
 name["english"] = "FreeBSD : SA-04:12.jailroute";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the FreeBSD kernel which
contains a bug which may allow a jailed process to modify the host routing
tables of the whole system.

Solution : http://www.vuxml.org/freebsd/fb5e227e-b8c6-11d8-b88c-000d610a3b12.html
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


if ( egrep(pattern:"FreeBSD-4\.9", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.9_10") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.[0-8]([^0-9]|$)", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.8_23") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}
