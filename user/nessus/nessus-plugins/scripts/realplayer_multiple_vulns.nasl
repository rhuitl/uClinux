#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17254);
 script_cve_id("CVE-2005-0455", "CVE-2005-0611");
 script_bugtraq_id(12697, 12698); 
 script_version("$Revision: 1.3 $");

 name["english"] = "RealPlayer Multiple Remote Overflows";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote Windows application is affected by several remote
overflows. 

Description :

According to its version number, the installed version of RealPlayer /
RealOne Player / RealPlayer Enterprise for Windows might allow an
attacker to execute arbitrary code and delete arbitrary files on the
remote host. 

To exploit these flaws, an attacker would send a malformed SMIL or WAV
file to a user on the remote host and wait for him to open it. 

See also : 

http://www.idefense.com/application/poi/display?id=209&type=vulnerabilities
http://www.securityfocus.com/archive/1/391959
http://service.real.com/help/faq/security/050224_player/EN/

Solution :

Upgrade according to the vendor advisories referenced above. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of RealPlayer";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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

  # There's a problem if the version is:
  #  - [6.0.11.0, 6.0.11.872], RealOne Player.
  #  - [6.0.12.0, 6.0.12.1059), RealPlayer
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 6 ||
    (
      int(iver[0]) == 6 &&
      int(iver[1]) == 0 &&
      (
        int(iver[2]) < 11 ||
        (int(iver[2]) == 11 && int(iver[3]) <= 872) ||
        (int(iver[2]) == 12 && int(iver[3]) < 1059)
      )
    )
  ) security_hole(port);
}
