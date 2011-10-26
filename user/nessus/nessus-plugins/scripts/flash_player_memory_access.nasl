#
# (C) Tenable Network Security
#


if (description) {
  script_id(20158);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2628", "CVE-2005-3591");
  script_bugtraq_id(15332, 15334);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18825");
  }

  script_name(english:"Flash Player Improper Memory Access Vulnerabilities");
  script_summary(english:"Checks for an improper memory access vulnerabilities in Flash Player");
 
  desc = "
Synopsis :

The remote host contains an application that is affected by remote
code execution flaws. 

Description :

According to its version number, the instance of Macromedia's Flash
Player on the remote host fails to validate the frame type identifier
from SWF files before using that as an index into an array of function
pointers.  An attacker may be able to leverage this issue using a
specially crafted SWF file to execute arbitrary code on the remote
host subject to the permissions of the user running Flash Player. 

See also :

http://research.eeye.com/html/advisories/published/AD20051104.html
http://www.sec-consult.com/228.html
http://www.macromedia.com/devnet/security/security_zone/mpsb05-07.html

Solution :

Upgrade to Flash Player versions 7r61 or 8 or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("flash_player_overflows.nasl");
  script_require_keys("MacromediaFlash/version");

  exit(0);
}

ver = get_kb_item("MacromediaFlash/version");

if (!isnull(ver))
{
  if (ereg(pattern:"^([0-6]\..*|7\.0\.([0-9]\.|[1-5][0-9]\.))", string:ver))
    security_warning(get_kb_item ("SMB/transport"));
}
