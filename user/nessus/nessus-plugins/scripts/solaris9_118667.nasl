#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19460);
 script_version ("$Revision: 1.1 $");
 name["english"] = "Solaris 9 (sparc) : 118667-02";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 118667-02
(118667-02 * J2SE 5.0 update 3 patch, 64bit).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-118667-02-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 118667-02"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e =  solaris_check_patch(release:"5.9", arch:"sparc", patch:"118667-02", obsoleted_by:"", package:"SUNWj5dmx SUNWj5dvx SUNWj5rtx");

if ( e < 0 ) security_hole(0);
