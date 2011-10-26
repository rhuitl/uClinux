#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22308);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-4554");
  script_bugtraq_id(19796);

  script_name(english:"Compression Plus Zoo Archive Processing Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of Compression Plus' cp5dll32.dll");

  desc = "
Synopsis :

There is a library file installed on the remote Windows host that is
affected by a buffer overflow vulnerability. 

Description :

The version of the Compression Plus toolkit installed on the remote
host contains a DLL that reportedly is prone to a stack-based overflow
when processing specially-crafted ZOO files.  Exploitation depends on
how the toolkit is used, especially with third-party products. 

See also :

http://www.mnin.org/advisories/2006_cp5_tweed.pdf
http://www.becubed.com/downloads/compfix.txt
https://kb1.tumbleweed.com/article.asp?article=4175&p=2

Solution :

Contact the vendor for a fix or upgrade Cp5dll32.dll to version
5.0.1.28 or later. 

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


sys_root = hotfix_get_systemroot();
if (!sys_root || !is_accessible_share()) exit(0);

if (
  hotfix_check_fversion(
    file    : "Cp5dll32.dll", 
    path    : sys_root + "\system32", 
    version : "5.0.1.28"
  ) == HCF_OLDER
) security_warning(get_kb_item("SMB/transport"));
hotfix_check_fversion_end();

