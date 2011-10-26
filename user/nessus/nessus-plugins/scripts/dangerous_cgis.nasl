#
# This script was written by John Lampe...j_lampe@bellsouth.net 
# Some entries were added by David Maciejak <david dot maciejak at kyxar dot fr>
#
# See the Nessus Scripts License for details
#
# Also covers :
# "CVE-1999-1374","CVE-2001-1283","CVE-2001-0076","CVE-2002-0710","CVE-2001-1100","CVE-2002-0346","CVE-2001-0133","CVE-2001-0022","CVE-2001-0420","CVE-2002-0203","CVE-2001-1343"
# "CVE-2002-0917","CVE-2003-0153","CVE-2003-0153","CVE-2000-0423","CVE-1999-1377","CVE-2001-1196","CVE-2002-1526","CVE-2001-0023","CVE-2002-0263","CVE-2002-0263","CVE-2002-0611",
# "CVE-2002-0230","CVE-2000-1131","CVE-2000-0288","CVE-2000-0952","CVE-2001-0180","CVE-2002-1334","CVE-2001-1205","CVE-2000-0977","CVE-2000-0526","CVE-2001-1100","CVE-2000-1023"
# ,"CVE-1999-0937","CVE-2001-0099","CVE-2001-0100","CVE-2001-1212","CVE-2000-1132","CVE-1999-0934","CVE-1999-0935"

if(description)
{
 script_id(11748);
 script_bugtraq_id(1784, 2177, 2197, 4211, 4579, 5078);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-1999-1072","CVE-2002-0749","CVE-2001-0135","CVE-2002-0955","CVE-2001-0562",
 		"CVE-2002-0346","CVE-2000-0923","CVE-2001-0123");
 
 
 name["english"] = "Various dangerous cgi scripts ";
 script_name(english:name["english"]);
 
 desc["english"] = "
Some of the following dangerous CGIs were found.

Solution : Please take the time to visit http://cve.mitre.org and check the 
associated CVE ID for each cgi found.  If you are running a vulnerable 
version, then delete or upgrade the CGI. 

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for dangerous cgi scripts";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK); 
 
 
 script_copyright(english:"This script is Copyright (C) 2003 John Lampe",
		francais:"Ce script est Copyright (C) 2003 John Lampe");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

if ( ! thorough_tests ) exit(0);

port = get_http_port(default:80);
if ( get_kb_item("www/no404/" + port ) || ! port) exit(0);

if(!get_port_state(port))exit(0);
cgi[0] = "AT-admin.cgi";     cve[0] = "CVE-1999-1072";
cgi[1] = "CSMailto.cgi";     cve[1] = "CVE-2002-0749";
cgi[2] = "UltraBoard.cgi";   cve[2] = "CVE-2001-0135";
cgi[3] = "UltraBoard.pl";    cve[3] = cve[2];
cgi[4] = "YaBB.cgi";         cve[4] = "CVE-2002-0955";
cgi[5] = "a1disp4.cgi";      cve[5] = "CVE-2001-0562";
cgi[6] = "alert.cgi";        cve[6] = "CVE-2002-0346";
cgi[7] = "authenticate.cgi"; cve[7] = "CVE-2000-0923";
cgi[8] = "bbs_forum.cgi";    cve[8] = "CVE-2001-0123";
cgi[9] = "bnbform.cgi";      cve[9] = "CVE-1999-0937";
cgi[10] = "bsguest.cgi";     cve[10] = "CVE-2001-0099";
cgi[11] = "bslist.cgi";      cve[11] = "CVE-2001-0100";
cgi[12] = "catgy.cgi";       cve[12] = "CVE-2001-1212";
cgi[13] = "cgforum.cgi";     cve[13] = "CVE-2000-1132";
cgi[14] = "classifieds.cgi"; cve[14] = "CVE-1999-0934";
cgi[15] = "csPassword.cgi";  cve[15] = "CVE-2002-0917";
cgi[16] = "cvsview2.cgi"  ;  cve[16] = "CVE-2003-0153";    
cgi[17] = "cvslog.cgi";      cve[17] = cve[16];
cgi[18] = "multidiff.cgi";   cve[18] = "CVE-2003-0153";
cgi[19]	= "dnewsweb.cgi";    cve[19] = "CVE-2000-0423";
cgi[20] = "download.cgi";    cve[20] = "CVE-1999-1377";
cgi[21] = "edit_action.cgi"; cve[21] = "CVE-2001-1196";
cgi[22] = "emumail.cgi";     cve[22] = "CVE-2002-1526";
cgi[23] = "everythingform.cgi"; cve[23] = "CVE-2001-0023";
cgi[24] = "ezadmin.cgi";     cve[24] = "CVE-2002-0263";
cgi[25] = "ezboard.cgi";     cve[25] = "CVE-2002-0263";
cgi[26] = "ezman.cgi";       cve[26] = cve[25];
cgi[27] = "ezadmin.cgi";     cve[27] = cve[25];
cgi[28] = "FileSeek.cgi";    cve[28] = "CVE-2002-0611";
cgi[29] = "fom.cgi";         cve[29] = "CVE-2002-0230";
cgi[30] = "gbook.cgi";	     cve[30] = "CVE-2000-1131";
cgi[31] = "getdoc.cgi";	     cve[31] = "CVE-2000-0288";
cgi[32] = "global.cgi";	     cve[32] = "CVE-2000-0952";
cgi[33] = "guestserver.cgi"; cve[33] = "CVE-2001-0180";
cgi[34] = "imageFolio.cgi";  cve[34] = "CVE-2002-1334";
cgi[35] = "lastlines.cgi";   cve[35] = "CVE-2001-1205";
cgi[36] = "mailfile.cgi";    cve[36] = "CVE-2000-0977";
cgi[37] = "mailview.cgi";    cve[37] = "CVE-2000-0526";
cgi[38] = "sendmessage.cgi"; cve[38] = "CVE-2001-1100";
cgi[39] = "nsManager.cgi";   cve[39] = "CVE-2000-1023";
cgi[40] = "perlshop.cgi";    cve[40] = "CVE-1999-1374";
cgi[41] = "readmail.cgi";    cve[41] = "CVE-2001-1283";
cgi[42] = "printmail.cgi";   cve[42] = cve[41];
cgi[43] = "register.cgi";    cve[43] = "CVE-2001-0076";
cgi[44] = "sendform.cgi";    cve[44] = "CVE-2002-0710";
cgi[45] = "sendmessage.cgi"; cve[45] = "CVE-2001-1100";
cgi[46] = "service.cgi";     cve[46] = "CVE-2002-0346";
cgi[47] = "setpasswd.cgi";   cve[47] = "CVE-2001-0133";
cgi[48] = "simplestmail.cgi"; cve[48] = "CVE-2001-0022";
cgi[49] = "simplestguest.cgi"; cve[49] = cve[48];
cgi[50] = "talkback.cgi";    cve[50] = "CVE-2001-0420";
cgi[51] = "ttawebtop.cgi";   cve[51] = "CVE-2002-0203";
cgi[52] = "ws_mail.cgi";     cve[52] = "CVE-2001-1343";
cgi[53] = "survey.cgi";      cve[53] = "CVE-1999-0936";
cgi[54] = "rxgoogle.cgi";    cve[54] = "CVE-2004-0251";
cgi[55] = "ShellExample.cgi"; cve[55] = "CVE-2004-0696";
cgi[56] = "Web_Store.cgi";   cve[56] = "CVE-2004-0734";
cgi[57] = "csFAQ.cgi";      cve[57] = "CVE-2004-0665";

flag = 0;
directory = "";

mymsg = string("\n\n", "The following dangerous CGI scripts were found", "\n");
mymsg += string("You should manually check each script and associated CVE ID at cve.mitre.org", "\n\n");

for (i = 0 ; cgi[i]; i = i + 1) {
	foreach dir (cgi_dirs()) {
   		if(is_cgi_installed_ka(item:string(dir, "/", cgi[i]), port:port)) {
  			flag = 1;
			mymsg = mymsg + string (dir, "/", cgi[i], " (", cve[i], ")\n");
   		} 
	}
} 


if (flag) {
    mymsg += string("\nSolution : Please take the time to visit cve.mitre.org and check the\n");
    mymsg += string("associated CVE ID for each cgi found.  If you are running a vulnerable\n");
    mymsg += string("version, then delete or upgrade the cgi.\n\n");
    security_hole(port:port, data:mymsg); 
    }
