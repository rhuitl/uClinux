#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15395);
 script_bugtraq_id(11307, 11308, 11309, 11335, 12311, 12315);
 script_version("$Revision: 1.10 $");

 name["english"] = "RealPlayer Remote Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote Windows application is affected by multiple remote
vulnerabilities. 

Description :

According to its version number, the installed version of RealPlayer /
RealOne Player for Windows may allow an attacker to execute arbitrary
code and delete arbitrary files on the remote host. 

See also :

http://www.service.real.com/help/faq/security/040928_player/EN/

Solution : 

Upgrade according to the vendor advisory referenced above.

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

  # There's a problem if the version is:
  #  - [6.0.12.0, 6.0.12.1053), RealPlayer 10.5
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 6 ||
    (
      int(iver[0]) == 6 &&
      int(iver[1]) == 0 &&
      (
        int(iver[2]) < 12 ||
        (int(iver[2]) == 12 && int(iver[3]) < 1053)
      )
    )
  ) security_hole(0);
}
