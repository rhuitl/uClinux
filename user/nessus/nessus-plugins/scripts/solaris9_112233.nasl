#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13510);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(10202, 10216, 5356, 6309, 8314, 8831, 9477, 9962);
 name["english"] = "Solaris 9 (sparc) : 112233-12";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 112233-12
( Kernel Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-112233-12-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 112233-12"; 
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

e =  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"FJSVhea SUNWarc SUNWarcx SUNWcar.m SUNWcar.u SUNWcar.us SUNWcarx.u SUNWcarx.us SUNWcpc.u SUNWcpc.us SUNWcpcx.u SUNWcpcx.us SUNWcpr.m SUNWcpr.u SUNWcpr.us SUNWcprx.u SUNWcprx.us SUNWcsl SUNWcslx SUNWcsr SUNWcstl SUNWcstlx SUNWcsu SUNWcsxu SUNWdrcrx.u SUNWdrr.u SUNWdrr.us SUNWdrrx.u SUNWdrrx.us SUNWefclx SUNWefcux SUNWefcx.u SUNWefcx.us SUNWfss SUNWfssx SUNWged SUNWgedu SUNWgedx SUNWhea SUNWidn.u SUNWidnx.u SUNWkvm.c SUNWkvm.d SUNWkvm.m SUNWkvm.u SUNWkvm.us SUNWmdb SUNWmdbx SUNWncar SUNWncarx SUNWncau SUNWncaux SUNWnfscr SUNWnfscx SUNWnisu SUNWpd SUNWpdx SUNWpiclu SUNWpmu SUNWpmux SUNWsxr.m SUNWusx.u SUNWwrsax.u SUNWwrsdx.u SUNWwrsmx.u SUNWwrsux.u");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-10202", value:TRUE);
	set_kb_item(name:"BID-10216", value:TRUE);
	set_kb_item(name:"BID-5356", value:TRUE);
	set_kb_item(name:"BID-6309", value:TRUE);
	set_kb_item(name:"BID-8314", value:TRUE);
	set_kb_item(name:"BID-8831", value:TRUE);
	set_kb_item(name:"BID-9477", value:TRUE);
	set_kb_item(name:"BID-9962", value:TRUE);
}
