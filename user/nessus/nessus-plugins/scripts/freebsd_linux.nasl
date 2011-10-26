#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12566);
 script_bugtraq_id(10643);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0602");
 name["english"] = "FreeBSD : SA-04:13.linux";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the FreeBSD kernel which 
contains a programming error in the way it handles some Linux system calls, 
which may be exploited by an attacker to gain super-user privileges on the
remote host, or to crash it.

Solution : http://www.vuxml.org/freebsd/8ecaaca2-cc07-11d8-858d-000d610a3b12.html
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

if ( egrep(pattern:"FreeBSD-4\.[0-8]([^0-9]|$)", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.8_24") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.9", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.9_11") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.10", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.10_2") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-5\.[012]", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.2.1_9") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

