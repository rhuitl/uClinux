#
#  (C) Tenable Network Security
#
#
# 
# - Thanks to stbjr -

if(description)
{
 script_id(12044);
 script_cve_id("CVE-2004-0258", "CVE-2004-0273");
 script_bugtraq_id(9579, 9580);
 
 script_version("$Revision: 1.4 $");

 name["english"] = "RealPlayer File Handler Code Execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote Windows application is affected by several remote flaws. 

Description :

According to its version number, the installed version of RealPlayer /
RealOne Player / RealPlayer Enterprise has a flaw that may allow an
attacker to execute arbitrary code on the remote host, with the
privileges of the user running RealPlayer, using specially-crafted RP,
RT, RAM, RPM or SMIL files. 

In addition, it may allow an attacker to download and execute
arbitrary code on the affected system using specially-crafted RMP
files. 

See also :

http://www.ngssoftware.com/advisories/realone.txt
http://archives.neohapsis.com/archives/fulldisclosure/2004-02/0442.html
http://service.real.com/help/faq/security/040123_player/EN/

Solution :

Upgrade according to the vendor advisories referenced above. 

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


include("smb_func.inc");
# Check version of RealPlayer.
ver = get_kb_item("SMB/RealPlayer/Version");
if (ver) {
  iver = split(ver, sep:'.', keep:FALSE);

  # There's a problem if the version is:
  #  - [6.0.11.0, 6.0.11.872), RealOne Player
  #  - [6.0.12.0, 6.0.12.690), Real Player
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 6 ||
    (
      int(iver[0]) == 6 &&
      int(iver[1]) == 0 &&
      (
        int(iver[2]) < 11 ||
        (int(iver[2]) == 11 && int(iver[3]) < 872) ||
        (int(iver[2]) == 12 && int(iver[3]) < 690)
      )
    )
  ) security_hole(kb_smb_transport());		
}
