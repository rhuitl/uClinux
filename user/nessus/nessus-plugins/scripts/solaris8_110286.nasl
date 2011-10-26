#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13340);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(3382, 5444, 5598);
 name["english"] = "Solaris 8 (sparc) : 110286-14";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 110286-14
( Tooltalk patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-110286-14-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 110286-14"; 
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

e =  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110286-14", obsoleted_by:"", package:"SUNWtltk SUNWtltkx");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-3382", value:TRUE);
	set_kb_item(name:"BID-5444", value:TRUE);
	set_kb_item(name:"BID-5598", value:TRUE);
}
