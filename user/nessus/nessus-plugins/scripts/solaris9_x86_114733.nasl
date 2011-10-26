#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13613);
 script_version ("$Revision: 1.7 $");
 name["english"] = "Solaris 9 (i386) : 114733-14";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 114733-14
( ufs and fsck Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-114733-14-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 114733-14"; 
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

e =  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114733-14", obsoleted_by:"117172-01", package:"SUNWcar.i SUNWcsr SUNWcsu SUNWhea");

if ( e < 0 ) security_hole(0);
