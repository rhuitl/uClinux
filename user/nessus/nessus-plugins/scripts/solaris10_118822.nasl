#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19367);
 script_version ("$Revision: 1.14 $");
 name["english"] = "Solaris 10 (sparc) : 118822-30";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 118822-30
( kernel Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-118822-30-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 118822-30"; 
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

e =  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"", package:"FJSVhea FJSVmdb FJSVmdbr FJSVpiclu SUNW1394 SUNWarcr SUNWcakr.u SUNWcakr.us SUNWcakr.v SUNWcart200.v SUNWckr SUNWcnetr SUNWcpr.u SUNWcsd SUNWcsl SUNWcslr SUNWcsr SUNWcsu SUNWcti2.u SUNWdfbh SUNWdrcr.u SUNWdrr.u SUNWdrr.us SUNWdtrc SUNWdtrp SUNWefc.u SUNWefc.us SUNWftdur SUNWhea SUNWib SUNWidn.u SUNWintgige SUNWipfr SUNWipfu SUNWkey SUNWluxl SUNWmdb SUNWmdbr SUNWmddr SUNWmdr SUNWmdu SUNWnfsckr SUNWopenssl-commands SUNWopenssl-libraries SUNWpcmci SUNWpiclu SUNWpl5v SUNWqos SUNWrcmdc SUNWscpu SUNWsndmr SUNWsndmu SUNWtoo SUNWusb SUNWust1.v SUNWwrsd.u SUNWwrsm.u SUNWxge");

if ( e < 0 ) security_hole(0);
