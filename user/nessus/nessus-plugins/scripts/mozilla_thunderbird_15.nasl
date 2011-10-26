#
# (C) Tenable Network Security
#


if (description) {
  script_id(20735);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0236");
  script_bugtraq_id(16271);

  script_name(english:"Mozilla Thunderbird < 1.5");
  script_summary(english:"Checks for Mozilla Thunderbird < 1.5");
 
  desc = "
Synopsis :

The remote version of Mozilla Thunderbird is affected by an attachment
spoofing vulnerability. 

Description :

The remote host is using Mozilla Thunderbird, an email client. 

The remote version of this software does not display attachments
correctly in emails.  Using an overly-long filename and
specially-crafted Content-Type headers, an attacker may be able to
leverage this issue to spoof the file extension and associated file
type icon and thereby trick a user into executing an arbitrary
program. 

See also : 

http://secunia.com/secunia_research/2005-22/advisory/
https://bugzilla.mozilla.org/show_bug.cgi?id=300246

Solution : 

Upgrade to Mozilla Thunderbird 1.5 or later.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}


ver = get_kb_item("Mozilla/Thunderbird/Version");
if (!ver) exit(0);

ver = split(ver, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 1 ||
  (int(ver[0]) == 1 && int(ver[1]) < 5)
) security_warning(get_kb_item("SMB/transport"));
