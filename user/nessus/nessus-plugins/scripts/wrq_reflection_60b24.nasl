#
# (C) Tenable Network Security
#


if (description) {
  script_id(19589);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2770", "CVE-2005-2771");
  script_bugtraq_id(14733, 14734, 14735);

  name["english"] = "AttachmateWRQ Reflection for Secure IT Server < 6.0 Build 24 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote SSH server is affected by multiple vulnerabilities.

Description :

The remote host is running AttachmateWRQ Reflection for Secure IT
Server, a commercial SSH server for Windows. 

According to its banner, the installed version of Reflection for
Secure IT Server on the remote host suffers from several
vulnerabilities, including :

  - An Access Restriction Bypass Vulnerability
    Access expressions are evaluated in a case-sensitive
    manner while in versions prior to 6.0 they were case-
    insensitive. This may let an attacker gain access
    to an otherwise restricted account by logging in
    using a variation on the account name.

  - A Renamed Account Remote Login Vulnerability
    The application continues to accept valid public keys
    for authentication to the the Administrator or Guest
    accounts if either has been renamed or disabled after
    being configured for SSH public key authentication, 

  - An Information Disclosure Vulnerability
    Users with access to the remote host can read the server's
    private key, which can lead to host impersonation attacks.

See also : 

http://support.wrq.com/techdocs/1867.html

Solution : 

Upgrade to Reflection for Secure IT Server 6.0 build 24 or later.

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in AttachmateWRQ Reflection for Secure IT Server < 6.0 build 24";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


port = get_kb_item("Services/ssh");
if (!port) port = 22;


banner = get_kb_item("SSH/banner/" + port);
if (banner) {
  if (egrep(string:banner, pattern:"WRQReflectionForSecureIT_([0-5]\.|6\.0 Build ([01]|2[0-3]))")) {
    security_note(port);
    exit(0);
  }
}
