#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15500);
 script_version ("$Revision: 1.1 $");
 name["english"] = "FreeBSD Ports : FreeRADIUS < 1.0.1";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has the following package installed :
	0.8.0 <= freeradius < 1.0.1


The remote version of this software is vulnerable to a flaw which may allow
an attacker to disable this service remotely.

Solution : http://www.vuxml.org/freebsd/20dfd134-1d39-11d9-9be9-000c6e8f12e.html
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the freeradius package";
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
if ( ! pkgs ) exit(0);

package = egrep(pattern:"^freeradius-[0-9]", string:pkgs);
if (package &&
    pkg_cmp(pkg:package, reference:"freeradius-0.8.0") >= 0 &&
    pkg_cmp(pkg:package, reference:"freeradius-1.0.1") <= 0 ) 
	{
	security_warning(0);
	exit(0);
	}
