#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13060);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(5912, 5937);
 script_cve_id("CVE-2002-1199");
 name["english"] = "Solaris 2.6 (i386) : 108891-02";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 108891-02
( ypxfrd, ypbind, and ypserv patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-108891-02-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 108891-02"; 
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

e =  solaris_check_patch(release:"5.6_x86", arch:"i386", patch:"108891-02", obsoleted_by:"", package:"SUNWnisu SUNWypu");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"CVE-2002-1199", value:TRUE);
	set_kb_item(name:"BID-5912", value:TRUE);
	set_kb_item(name:"BID-5937", value:TRUE);
}
