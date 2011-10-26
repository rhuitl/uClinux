#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15419);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(11321);
 script_cve_id("CVE-2004-0919");
 name["english"] = "FreeBSD : SA-04:15.syscons";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of FreeBSD which contains a flaw in the 
syscons console driver.

There are boundary errors in the CONS_SCRSHOT ioctls which may allow a local
attacker to read portions of the kernel memory, which may contains sensitive
informations.

Solution : http://www.vuxml.org/freebsd/67710833-1626-11d9-bc4a-000c41e2cdad.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the FreeBSD";
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

if ( ! package ) exit(0);


if ( egrep(pattern:"FreeBSD-5\.", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.2.1_11") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

