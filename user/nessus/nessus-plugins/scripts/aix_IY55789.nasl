#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14438);
 script_version ("$Revision: 1.2 $");
 name["english"] = "AIX 5.2 : IY55789";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing AIX Critical Security Patch number IY55789
(SECURITY: Symlink vulnerability in console commands).

You should install this patch for your system to be up-to-date.

Solution : http://www-912.ibm.com/eserver/support/fixes/ 
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch IY55789"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "AIX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");

 if( aix_check_patch(release:"5.2", patch:"IY55789", package:"bos.rte.console.5.2.0.11 bos.rte.serv_aid.5.2.0.31") < 0 ) 
   security_hole(port);
