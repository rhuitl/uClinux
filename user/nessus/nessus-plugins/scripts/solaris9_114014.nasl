#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13546);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(13748);
 name["english"] = "Solaris 9 (sparc) : 114014-10";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 114014-10
( libxml, libxslt and Freeware man pages Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-114014-10-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 114014-10"; 
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

e =  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114014-10", obsoleted_by:"", package:"SUNWlxml SUNWlxmlS SUNWlxmlx SUNWlxsl SUNWlxslx SUNWsfman");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-13748", value:TRUE);
}
