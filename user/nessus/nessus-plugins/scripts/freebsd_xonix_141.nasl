#
# (C) Tenable Network Security
#
#
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14281);
 script_bugtraq_id(10149);
 script_cve_id("CVE-2004-0157");
 script_version ("$Revision: 1.4 $");

 name["english"] = "FreeBSD Xonix vulnerability";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running an older version of Xonix.

Xonix is a game.

This version of Xonix calls an external program while retaining
setgid privileges.  An attacker, exploiting this flaw, would need
local access.  A successful attack would give the attacker the
privileges of the 'games' group.

Solution : http://www.vuxml.org/freebsd/6fd9a1e9-efd3-11d8-9837-000c41e2cdad.html 
 
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "FreeBSD Xonix local exploit";
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
package = egrep(pattern:"^xonix-", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"xonix-1.4_1") < 0 )
        security_warning(0);



