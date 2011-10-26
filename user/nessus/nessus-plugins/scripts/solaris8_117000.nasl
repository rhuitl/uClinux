#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13406);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Solaris 8 (sparc) : 117000-05";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 117000-05
( Kernel Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-117000-05-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 117000-05"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e =  solaris_check_patch(release:"5.8", arch:"sparc", patch:"117000-05", obsoleted_by:"", package:"FJSVhea SUNWcar.d SUNWcar.m SUNWcar.u SUNWcar.us SUNWcarx.u SUNWcarx.us SUNWcpc.u SUNWcpc.us SUNWcpcx.u SUNWcpcx.us SUNWcpr.m SUNWcpr.u SUNWcprx.u SUNWcsr SUNWcsu SUNWcsxu SUNWdrr.u SUNWdrr.us SUNWdrrx.u SUNWdrrx.us SUNWged SUNWgedu SUNWhea SUNWidn.u SUNWidnx.u SUNWmdb SUNWmdbx SUNWncar SUNWncarx SUNWusx.u SUNWwrsax.u SUNWwrsmx.u");

if ( e < 0 ) security_hole(0);
