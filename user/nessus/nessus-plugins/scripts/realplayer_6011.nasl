#
#  (C) Tenable Network Security
#

if(description)
{
 script_id(14278);
 script_version("$Revision: 1.4 $");

 script_cve_id("CVE-2004-0550");
 script_bugtraq_id(10527, 10528, 10934);
 

 name["english"] = "RealPlayer multiple remote overflows";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote Windows application is affected by several remote
overflows. 

Description :

According to its version number, the installed version of RealPlayer
on the remote host is vulnerable to several overflows.  In exploiting
these flaws, an attacker would need to be able to coerce a local user
into visiting a malicious URL or downloading a malicious media file
which, upon execution, would execute code with the privileges of the
local user. 

See also :

http://www.securityfocus.com/archive/1/365709/2004-06-07/2004-06-13/0
http://www.idefense.com/application/poi/display?id=109&type=vulnerabilities
http://service.real.com/help/faq/security/040610_player/EN/
http://www.eeye.com/html/research/upcoming/20040811.html

Solution : 

Unknown at this time. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of RealPlayer";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("realplayer_detect.nasl");
 script_require_keys("SMB/RealPlayer/Version");

 exit(0);
}


# Check version of RealPlayer.
ver = get_kb_item("SMB/RealPlayer/Version");
if (ver) {
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) == 6 && int(iver[1]) == 0 && 
    (
      (int(iver[2]) == 10 && int(iver[3]) == 505) ||
      (
        int(iver[2]) == 11 && 
        (int(iver[3]) >= 818 && int(iver[3]) <= 872)
      )
    )
  ) security_hole(port);
}
