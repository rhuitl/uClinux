#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12614);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-b-0008");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-b-0005");
 script_bugtraq_id(9586, 9792);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0171");
 name["english"] = "FreeBSD : SA-04:02.shmat";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the FreeBSD kernel which may be
contains a programming error in the shmat(2) system call which can 
let a local attacker to gain read or write access to a portion of the
kernel memory which in turn might be used to elevate his privileges
or gain access to sensitive information.

Solution : http://www.vuxml.org/freebsd/f95a9005-88ae-11d8-90d1-0020ed76ef5a.html
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

if ( egrep(pattern:"FreeBSD-4\.[0-7]([^0-9]|$)", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.7_25") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.8", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.8_15") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.9", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.9_2") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-5\.0", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.0_20") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-5\.1", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.1_14") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-5\.2", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.2_2") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}
