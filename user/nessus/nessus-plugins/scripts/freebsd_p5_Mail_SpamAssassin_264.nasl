#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14345);
 script_bugtraq_id(10957);
 script_version ("$Revision: 1.2 $");
 name["english"] = "FreeBSD Ports : p5-Mail-SpamAssassin < 2.64";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the p5-Mail-SpamAssassin package
which is older than version 2.64.


SpamAssassin is a spam filter. There is a denial of service condition in the
remote version of this package which may allow an attacker to cause it to
crash by sending a malformed email message. 

If the remote host is configured to run SpamAssassin as a daemon (through
spamd), an attacker may cause a loss of email messages by sending a malformed
message.

There is a heap overflow in the remote version of this package (in the
BMP, GIF, XPM and JPEG decoders) which may allow an attacker to
execute arbitrary code on the remote host.

Solution : http://www.vuxml.org/freebsd/0d3a5148-f512-11d8-9837-000c41e2cdad.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the SpamAssassin package";
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


package = egrep(pattern:"^p5-Mail-SpamAssassin\.", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"p5-Mail-SpamAssassin-2.64") < 0 ) 
        {
        security_hole(0);
        exit(0);
        }
