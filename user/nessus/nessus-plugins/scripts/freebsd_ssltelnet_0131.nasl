#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12617);
 script_bugtraq_id(10684);
 script_version ("$Revision: 1.3 $");


 name["english"] = "FreeBSD Ports : SSLtelnet <= 0.13.1";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has an old version of the package SSLtelnet installed (older 
than version 0.13_2).

SSLtelnet is a SSL enhanced telnet daemon. There are multiple vulnerabilities
in the remote version of this software which may allow an attacker to execute
arbitrary code on the remote host, by exploiting a format string vulnerability
which is contained in the SSLtelnetd code.

Solution : http://www.vuxml.org/freebsd/4aec9d58-ce7b-11d8-858d-000d610a3b12.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the SSLtelnet package";
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
package = egrep(pattern:"^SSLtelnet-", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"SSLtelnet-0.13_1") <= 0 ) 
	security_hole(0);
