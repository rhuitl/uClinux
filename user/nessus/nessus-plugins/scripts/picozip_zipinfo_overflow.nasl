#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21697);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-2909");
  script_bugtraq_id(18425);
  script_xref(name:"OSVDB", value:"26447");

  script_name(english:"PicoZip ZipInfo.dll Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of PicoZip");

  desc = "
Synopsis :

The remote Windows host contains an application that is affected by a
buffer overflow. 

Description :

The remote host is running PicoZip, a file compression utility for
Windows. 

According to the registry, the version of PicoZip installed on the
remote Windows host fails to properly check the size of filenames
before copying them into a finite-sized buffer within the
'zipinfo.dll' info tip shell extension.  Using a specially-crafted
ACE, RAR, or ZIP file, an attacker may be able to exploit this issue
to execute arbitrary code on the affected host subject to the
privileges of the user running the affected application. 

See also :

http://secunia.com/secunia_research/2006-42/advisory/
http://www.picozip.com/changelog.html

Solution : 

Upgrade to PicoZip version 4.02 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for evidence of PicoZip.
name = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Acubix PicoZip_is1/DisplayName");
if (name && name =~ "PicoZip ([0-3]\.|4\.0($|[01]([^0-9]|$)))")
  security_warning(get_kb_item("SMB/transport"));
