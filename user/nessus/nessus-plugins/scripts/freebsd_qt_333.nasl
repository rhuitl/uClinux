#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14340);
 script_bugtraq_id(10977);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");
 name["english"] = "FreeBSD Ports : Qt < 3.3.3";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running an older version of the qt package.

Qt is a software toolkit that simplifies the task of writing and maintaining
GUI applications for the X Window System.

There is a heap overflow in the remote version of this package (in the
BMP, GIF, XPM and JPEG decoders) which may allow an attacker to
execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to craft a malformed image
file and to send it to a victim on the remote host, and have the victim
open the file with a Qt-enabled application.

Solution : http://www.vuxml.org/freebsd/ebffe27a-f48c-11d8-9837-000c41e2cdad.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the qt package";
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

package = egrep(pattern:"^qt-3\.", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"qt-3.3.3") < 0 ) 
        {
        security_hole(0);
        exit(0);
        }
