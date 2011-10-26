#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13418);
 script_version ("$Revision: 1.34 $");
 script_bugtraq_id(7064, 7123, 8253, 9757);
 name["english"] = "Solaris 8 (i386) : 108994-62";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 108994-62
( LDAP2 client, libc, libthread and libnsl libraries patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-108994-62-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 108994-62"; 
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

e =  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108994-62", obsoleted_by:"", package:"");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-7064", value:TRUE);
	set_kb_item(name:"BID-7123", value:TRUE);
	set_kb_item(name:"BID-8253", value:TRUE);
	set_kb_item(name:"BID-9757", value:TRUE);
}
