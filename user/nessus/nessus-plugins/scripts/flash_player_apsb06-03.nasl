#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21079);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0024");
  script_bugtraq_id(17106);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"23908");

  script_name(english:"Flash Player APSB06-03");
  script_summary(english:"Checks version of Flash Player");
 
  desc = "
Synopsis :

The remote Windows host contains a browser plugin that is affected by
several critical flaws. 

Description :

According to its version number, the instance of Flash Player on the
remote Windows host contains multiple critical and as-yet unspecified
vulnerabilities that could allow an attacker to take control of the
affected host.  To exploit these issues, a user must load a malicious
SWF file in Flash Player. 

See also :

http://www.microsoft.com/technet/security/Bulletin/MS06-020.mspx
http://www.microsoft.com/technet/security/advisory/916208.mspx
http://www.macromedia.com/devnet/security/security_zone/apsb06-03.html

Solution :

Upgrade to Flash Player version 7.0.63.0 / 8.0.24.0 or later. 

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("flash_player_overflows.nasl");
  script_require_keys("MacromediaFlash/version");

  exit(0);
}


ver = get_kb_item("MacromediaFlash/version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) < 6 ||
  (int(iver[0]) == 6 && int(iver[1]) == 0 && int(iver[2]) < 84) ||
  (int(iver[0]) == 7 && int(iver[1]) == 0 && int(iver[2]) < 63) ||
  (int(iver[0]) == 8 && int(iver[1]) == 0 && int(iver[2]) < 24)
) security_warning(get_kb_item("SMB/transport"));

