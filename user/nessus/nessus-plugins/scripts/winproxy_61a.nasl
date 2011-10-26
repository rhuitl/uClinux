#
# (C) Tenable Network Security
#


if (description) {
  script_id(20393);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-3187", "CVE-2005-3654", "CVE-2005-4085");
  script_bugtraq_id(16147, 16148, 16149);

  script_name(english:"WinProxy < 6.1a Multiple Vulnerabilities (registry check)");
  script_summary(english:"Checks for multiple vulnerabilities in WinProxy < 6.1a");

  desc = "
Synopsis :

The remote proxy is affected by multiple vulnerabilities. 

Description :

The remote host is running WinProxy, a proxy server for Windows. 

According to the Windows registry, the installed version of WinProxy
suffers from denial of service and buffer overflow vulnerabilities in its
telnet and web proxy servers. An attacker may
be able to exploit these issues to crash the proxy or even execute
arbitrary code on the affected host. 

See also :

http://www.idefense.com/intelligence/vulnerabilities/display.php?id=363
http://www.idefense.com/intelligence/vulnerabilities/display.php?id=364
http://www.idefense.com/intelligence/vulnerabilities/display.php?id=365
http://www.winproxy.com/products/relnotes.asp

Solution : 

Upgrade to WinProxy version 6.1a or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for evidence of WinProxy.
name = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/WinProxy 6/DisplayName");
if (name && name =~ "^WinProxy \(Version ([0-5]\.|6\.0)") {
  security_warning(0);
  exit(0);
}

