#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21698);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-3093");
  script_bugtraq_id(18445);
  script_xref(name:"OSVDB", value:"26536");

  script_name(english:"Adobe Reader < 7.0.8");
  script_summary(english:"Checks version of Adobe Reader");

  desc = "
Synopsis :

The PDF file viewer on the remote Windows host is affected by several issues.

Description :

The version of Adobe Reader installed on the remote host is earlier than 7.0.8
and thus reportedly is affected by several security issues. While details on
the nature of these flaws is currently unknown, the vendor ranks them low,
saying they have minimal impact and are difficult to exploit.

See also :

http://www.adobe.com/support/techdocs/327817.html

Solution : 

Upgrade to Adobe Reader 7.0.8 or later. 

Risk factor : 

Medium / CVSS Base Score : 4.8
(AV:L/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");

  exit(0);
}


ver = get_kb_item("SMB/Acroread/Version");
if (
  ver && 
  ver =~ "^([0-6]\.|7\.0\.[0-7][^0-9.]?))"
) security_warning(get_kb_item("SMB/transport"));
