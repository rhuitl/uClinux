#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14588);
 script_version ("$Revision: 1.2 $");

 name["english"] = "FreeBSD Ports : ImageMagick < 6.0.6.2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the ImageMagick package which is
older than version 6.0.6.2.

ImageMagick is a set of image processing tools. There is a heap overflow
in the remote version of this package when it processes a specially
crafted BMP file. An attacker may exploit this flaw to execute arbitrary
code on the remote host.

To exploit this flaw, an attacker would need to craft a malformed image
file and to send it to a victim on the remote host, and have the victim
open the file with this software.

Solution : http://www.vuxml.org/freebsd/b6cad7f3-fb59-11d8-9837-000c41e2cdad.html
Risk Factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ImageMagick package";
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

package = egrep(pattern:"^ImageMagick-", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"ImageMagick-6.0.6.2") < 0 ) 
        {
        security_hole(0);
        exit(0);
        }
