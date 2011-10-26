#
#  (C) Tenable Network Security
#
#

if(description)
{
 script_id(15789);

 script_cve_id("CVE-2004-1094");
 script_bugtraq_id(11555);
 script_xref(name:"OSVDB", value:"19906");
 
 script_version("$Revision: 1.8 $");

 name["english"] = "RealPlayer Skin File Remote Buffer Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote Windows application is affected by a remote buffer
overflow. 

Description :

According to its version number, the installed version of RealPlayer /
RealOne Player for Windows may allow an attacker to execute arbitrary
code on the remote host, with the privileges of the user running
RealPlayer because of an overflow vulnerability in the third-party
compression library 'DUNZIP32.DLL'. 

To do so, an attacker would need to send a corrupted skin file (.RJS)
to a remote user and have him open it using RealPlayer. 

See also :

http://archives.neohapsis.com/archives/fulldisclosure/2004-10/1044.html
http://service.real.com/help/faq/security/041026_player/EN/

Solution : 

Upgrade according to the vendor advisories referenced above.

Risk factor :

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of RealPlayer";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
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
  #  - [6.0.12.0, 6.0.12.1056), Real Player
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 6 ||
    (
      int(iver[0]) == 6 &&
      int(iver[1]) == 0 &&
      (
        int(iver[2]) < 12 ||
        (int(iver[2]) == 12 && int(iver[3]) < 1056)
      )
    )
  ) security_hole(kb_smb_transport());
}
