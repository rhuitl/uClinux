#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22875);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4819");
  script_bugtraq_id(20591);

  script_name(english:"Opera < 9.02 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  desc = "
Synopsis :

The remote host contains a web browser which is susceptible to a heap
buffer overflow attack. 

Description :

The version of Opera installed on the remote host reportedly contains
a heap buffer overflow vulnerability that can be triggered by a long
link.  Successful exploitation of this issue may result in a crash of
the application or even allow for execution of arbitrary code subject
to the user's privileges. 

See also :

http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=424
http://archives.neohapsis.com/archives/fulldisclosure/2006-10/0347.html
http://www.opera.com/support/search/supsearch.dml?index=848

Solution :

Upgrade to Opera version 9.02 or later. 

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}


ver = get_kb_item("SMB/Opera/Version");
if (ver && ver =~ "^9\.0[01]$")
  security_warning(get_kb_item("SMB/transport"));
