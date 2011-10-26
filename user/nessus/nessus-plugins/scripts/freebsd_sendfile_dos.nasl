#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17984);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(12993);
 script_cve_id("CVE-2005-0708");
 name["english"] = "FreeBSD : SA-05:02.sendfile";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of FreeBSD which contains a flaw in the 
sendfile() API.

There is an error in the sendfile() API which may allow a local user to disclose
parts of the contents of the kernel memory.

Solution : http://www.securityfocus.com/advisories/8356
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the FreeBSD";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}



include("freebsd_package.inc");


package = get_kb_item("Host/FreeBSD/release");

if ( ! package ) exit(0);


if ( egrep(pattern:"FreeBSD-5\.", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.3_7") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.[0-7][^0-9]", string:package) )
{
 security_hole(port);
 exit(0);
}

if ( egrep(pattern:"FreeBSD-4\.8[^0-9]", string:package) ) 
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.8_29") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}


if ( egrep(pattern:"FreeBSD-4\.(9|10)", string:package) ) 
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.10_7") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}


if ( egrep(pattern:"FreeBSD-4\.11", string:package) ) 
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.11_2") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

