#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13334);
 script_version ("$Revision: 1.9 $");
 name["english"] = "Solaris 8 (sparc) : 109896-30";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 109896-30
( USB and Audio Framework patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-109896-30-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 109896-30"; 
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

e =  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109896-30", obsoleted_by:"", package:"SUNWauda SUNWaudd SUNWauddx SUNWaudh SUNWcar.u SUNWcar.us SUNWcarx.u SUNWcarx.us SUNWcsr SUNWcsu SUNWcsxu SUNWmdb SUNWmdbx SUNWuaud SUNWuaudx SUNWusb SUNWusbu SUNWusbx");

if ( e < 0 ) security_hole(0);
