#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13123);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(4088, 4932, 4933);
 name["english"] = "Solaris 7 (sparc) : 107709-27";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 107709-27
( libssasnmp/libssagent/snmpdx/snmpXdmid/mibiisa Patches).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-107709-27-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 107709-27"; 
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

e =  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107709-27", obsoleted_by:"", package:"SUNWmibii SUNWsacom SUNWsadmi SUNWsadmx SUNWsasnm SUNWsasnx");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-4088", value:TRUE);
	set_kb_item(name:"BID-4932", value:TRUE);
	set_kb_item(name:"BID-4933", value:TRUE);
}
