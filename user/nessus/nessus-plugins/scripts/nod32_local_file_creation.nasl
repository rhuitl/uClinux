#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21609);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1649");
  script_bugtraq_id(17374);
  script_xref(name:"OSVDB", value:"24393");

  script_name(english:"NOD32 Antivirus Local File Creation Vulnerability");
  script_summary(english:"Checks version number of NOD32");

  desc = "
Synopsis :

The remote Windows host contains an application that is subject to a
local privilege escalation attack. 

Description :

The installed version of NOD32 reportedly allows a local user to
restore a malicious file from NOD32's quarantine to an arbitrary
directory to which the user otherwise has only read access.  A local
user can exploit this issue to gain admin/system privilege on the
affected host. 

See also :

http://www.securityfocus.com/archive/1/429892/30/0/threaded

Solution :

Upgrade to NOD32 version 2.51.26 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:L/AC:L/Au:NR/C:C/I:C/A:C/B:N)";
  script_description(english:desc);
 

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("nod32_installed.nasl");

  exit(0);
}


ver = get_kb_item("Antivirus/NOD32/version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) < 2 ||
  (
    int(iver[0]) == 2 &&
    (
      int(iver[1]) < 51 ||
      (int(iver[1]) == 51 && int(iver[2]) < 26)
    )
  )
) security_warning(get_kb_item("SMB/transport"));
