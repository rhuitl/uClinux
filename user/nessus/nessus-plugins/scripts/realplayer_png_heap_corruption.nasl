#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11496);
 script_bugtraq_id(7177);
 script_cve_id("CVE-2003-0141");  
 
 script_version("$Revision: 1.5 $");

 name["english"] = "RealPlayer PNG deflate heap corruption";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote Windows application is affected by a heap corruption
vulnerability. 

Description :

According to its version number, the installed version of RealPlayer /
RealOne Player / RealPlayer Enterprise for Windows has a flaw in the
remote version that may allow an attacker to execute arbitrary code on
the remote host, with the privileges of the user running RealPlayer. 

To do so, an attacker would need to send a corrupted PNG file to a
remote user and have him open it using RealPlayer. 

See also :

http://www.coresecurity.com/common/showdoc.php?idx=311&idxseccion=10
http://service.real.com/help/faq/security/securityupdate_march2003.html

Solution :

Upgrade according to the vendor advisories referenced above. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of RealPlayer";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
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
  #  - [6.0.9.0, 6.0.9.584], RealPlayer 8
  #  - [6.0.10.0, 6.0.10.505], RealOne Player
  #  - [6.0.11.0, 6.0.11.774], RealOne Enterprise
  #  - [6.0.11.818, 6.0.11.853], RealOne Player version 2
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 6 ||
    (
      int(iver[0]) == 6 &&
      int(iver[1]) == 0 &&
      (
        int(iver[2]) < 8 ||
        (int(iver[2]) == 9 && int(iver[3]) <= 584) ||
        (int(iver[2]) == 10 && int(iver[3]) <= 505) ||
        (int(iver[2]) == 11 && int(iver[3]) <= 774) ||
        (int(iver[2]) == 11 && int(iver[3]) >= 818 && int(iver[3]) <= 853)
      )
    )
  ) security_hole(port);
}
