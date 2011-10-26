#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14351);
 script_bugtraq_id(10890);
 script_version ("$Revision: 1.2 $");
 name["english"] = "FreeBSD Ports: libxine < 1.0r5_2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has an old version of libxine installed.

libxine is a set of libraries for the Xine multimedia player. There is a buffer
overflow condition in the remote version of this library which may allow
an attacker to execute arbitrary code on the remote host when a libxine-enabled
application processes a malformed vcd:// input source indentifier.

To exploit this flaw, an attacker would need to send a malicious playlist file
to a Xine user on the remote host, containing a malformed vcd:// link.

Solution : http://www.vuxml.org/freebsd/bef4515b-eaa9-11d8-9440-000347a4fa7d.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libxine package";
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

package = egrep(pattern:"^libxine-", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"libxine-1.0.r5_2") < 0 ) security_hole(0);
