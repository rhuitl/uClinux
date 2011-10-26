#
# (C) Tenable Network Security
#


if (description) {
  script_id(19766);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-3006", "CVE-2005-3007", "CVE-2005-3041");
  script_bugtraq_id(14880, 14884);
  script_xref(name:"OSVDB", value:"19508");
  script_xref(name:"OSVDB", value:"19509");

  name["english"] = "Opera < 8.50 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host contains a web browser which is vulnerable to
attachment spoofing, script insertion and unintentional file uploads. 

Description :

The remote host is using Opera, an alternative web browser. 

The installed version of Opera on the remote host contains two flaws
its mail client and one in the browser.  First, message attachments
are opened from the user's cache directory without any warnings, which
can be exploited to execute arbitrary Javascript within the context of
'file://'.  Second, appending an additional '.' to an attachment's
filename causes the file type to be spoofed.  And third, the browser
is affected by an unspecified drag-and-drop vulnerability that
facilitates unintentional file uploads. 

See also :

http://secunia.com/secunia_research/2005-42/advisory/
http://www.opera.com/docs/changelogs/windows/850/

Solution : 

Upgrade to Opera 8.50 or later.

Risk factor : 

Medium / CVSS Base Score : 4
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Opera < 8.50";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}


ver = get_kb_item("SMB/Opera/Version");
if (ver && ver =~ "^([0-7]\.|8\.[0-4][^0-9]?)")
  security_warning(get_kb_item("SMB/transport"));
