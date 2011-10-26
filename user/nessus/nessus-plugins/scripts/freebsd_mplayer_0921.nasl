#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12581);
 script_bugtraq_id(10008);
 script_version ("$Revision: 1.3 $");
 name["english"] = "FreeBSD Ports: mplayer < 0.92.1";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has an old version of mplayer installed.

mplayer is a movie player. There is a bug in the remote version of this software
in the way it decodes URLs. If an attacker can cause mplayer to visit a 
specially crafter URL, arbitrary code execution with the privileges of the
mplayer user is possible.

Solution : http://www.vuxml.org/freebsd/5e7f58c3-b3f8-4258-aeb8-795e5e940ff8.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mplayer packages";
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

package = egrep(pattern:"^mplayer-", string:pkgs);
lines = split(package, sep:'\n', keep:0);
foreach package (lines )
{
if ( pkg_cmp(pkg:package, reference:"mplayer-0.92.1") < 0 ) 
	{
	security_hole(0);
	exit(0);
	}
}
