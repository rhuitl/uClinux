#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12530);
 script_bugtraq_id(10384);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0396");
 name["english"] = "FreeBSD : SA-04:10.cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of FreeBSD which contains a
heap overflow in the cvs pserver code. This flaw may be used by an attacker
to execute arbitrary code on the remote host, provided that it's running
a cvs pserver.

Solution : http://www.vuxml.org/freebsd/f93be979-a992-11d8-aecc-000d610a3b12.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of FreeBSD";
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

pkgs = get_kb_item("Host/FreeBSD/pkg_info");

package = get_kb_item("Host/FreeBSD/release");


if ( egrep(pattern:"FreeBSD-5\.2", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.2_7") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-5\.1", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.1_17") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-5\.0", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.0_21") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.9", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.9_8") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.8", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.8_21") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.[0-7]([^0-9]|$)", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.7_27") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

