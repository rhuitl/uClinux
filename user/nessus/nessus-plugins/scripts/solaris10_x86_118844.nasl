#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19370);
 script_version ("$Revision: 1.11 $");
 name["english"] = "Solaris 10 (i386) : 118844-30";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 118844-30
( kernel Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-118844-30-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 118844-30"; 
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

e =  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"", package:"CADP160 SUNW1394 SUNWadp SUNWarcr SUNWcadp SUNWcakr.i SUNWckr SUNWcnetr SUNWcpcu SUNWcsd SUNWcsl SUNWcslr SUNWcsr SUNWcsu SUNWdfbh SUNWdtrc SUNWdtrp SUNWesu SUNWftdur SUNWhea SUNWib SUNWintgige SUNWipfr SUNWipfu SUNWkdcu SUNWkey SUNWkrbu SUNWkvm.i SUNWmdb SUNWmdbr SUNWmddr SUNWmdr SUNWmdu SUNWnfsckr SUNWopenssl-commands SUNWopenssl-libraries SUNWos86r SUNWpcmci SUNWpiclu SUNWpsdcr SUNWpsdir SUNWpsh SUNWqos SUNWradpu320 SUNWrcapu SUNWrcmdc SUNWrmodr SUNWrmodu SUNWrmwbu SUNWscpu SUNWsndmr SUNWsndmu SUNWtnfc SUNWtoo SUNWusb SUNWxge");

if ( e < 0 ) security_hole(0);
