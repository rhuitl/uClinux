#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22056);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-3014", "CVE-2006-3311", "CVE-2006-3587", "CVE-2006-3588", "CVE-2006-4640");
  script_bugtraq_id(18894, 19980);

  script_name(english:"Flash Player < 9.0");
  script_summary(english:"Checks version of Flash Player");
 
  desc = "
Synopsis :

The remote Windows host contains a browser plugin that is affected by
multiple issues. 

Description :

According to its version number, the instance of Flash Player on the
remote Windows host is affected by arbitrary code execution and denial
of service flaws.  By convincing a user to visit a site with a
specially-crafted SWF file, an attacker may be able to execute
arbitrary code on the affected host or cause the web browser to crash. 

See also :

http://www.fortinet.com/FortiGuardCenter/advisory/FG-2006-20.html
http://www.fortinet.com/FortiGuardCenter/advisory/FG-2006-21.html
http://www.kb.cert.org/vuls/id/474593
http://www.adobe.com/support/security/bulletins/apsb06-11.html

Solution :

Upgrade to Flash Player 9.0 or later. 

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
if (ver && ver =~ "^[0-8]\.")
  security_warning(get_kb_item("SMB/transport"));

