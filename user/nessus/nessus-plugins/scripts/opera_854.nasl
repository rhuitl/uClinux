#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21221);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1834");
  script_bugtraq_id(17513);

  script_name(english:"Opera < 8.54 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");
 
  desc = "
Synopsis :

The remote host contains a web browser which is vulnerable to a buffer
overflow vulnerability. 

Description :

The remote host is using Opera, an alternative web browser. 

The version of Opera installed on the remote host contains a buffer
overflow that can be triggered by a long value within a stylesheet
attribute.  Successful exploitation can lead to a browser crash and
possibly allow for the execution of arbitrary code subject to the
privileges of the user running Opera. 

See also :

http://www.securityfocus.com/archive/1/430876/30/0/threaded
http://www.opera.com/docs/changelogs/windows/854/

Solution :

Upgrade to Opera 8.54 or later. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}


ver = get_kb_item("SMB/Opera/Version");
if (ver && ver =~ "^([0-7]\.|8\.([0-4]|5[0-3])[^0-9]?)")
  security_warning(get_kb_item("SMB/transport"));
