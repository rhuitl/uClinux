#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13517);
 script_version ("$Revision: 1.15 $");
 name["english"] = "Solaris 9 (sparc) : 112817-29";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 112817-29
( Sun GigaSwift Ethernet 1.0 driver patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-112817-29-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 112817-29"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e =  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112817-29", obsoleted_by:"", package:"SUNWcea SUNWceax SUNWced.u SUNWced.us SUNWcedu SUNWcedx.u SUNWcedx.us");

if ( e < 0 ) security_hole(0);
