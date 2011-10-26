#
# (C) Tenable Network Security
#


if (description) {
  script_id(20902);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0705");
  script_bugtraq_id(16625);

  script_name(english:"AttachmateWRQ Reflection for Secure IT Server SFTP Format String Vulnerability");
  script_summary(english:"Checks for format string vulnerability in AttachmateWRQ Reflection for Secure IT Server SFTP subsystem");
 
  desc = "
Synopsis :

The remote SSH server is affected by a format string vulnerability. 

Description :

The remote host is running AttachmateWRQ Reflection for Secure IT
Server / F-Secure SSH Server, a commercial SSH server. 

According to its banner, the installed version of this software
contains a format string vulnerability in its sftp subsystem.  A
remote, authenticated attacker may be able to execute arbitrary code
on the affected host subject to his privileges or crash the server
itself. 

See also : 

http://support.wrq.com/techdocs/1882.html
http://www.kb.cert.org/vuls/id/419241

Solution : 

Either upgrade as described in the vendor advisory above or edit the
software's configuration to disable the SFTP subsystem. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


port = get_kb_item("Services/ssh");
if (!port) port = 22;


banner = get_kb_item("SSH/banner/" + port);
if (banner) {
  if ("ReflectionForSecureIT" >< banner) {
    if (
      # Reflection for Secure IT Windows Server versions 6.x < 6.0 build 38.
      egrep(pattern:"WRQReflectionForSecureIT_6\.0 Build ([0-2]|3[0-4])", string:banner) ||
      # Reflection for Secure IT UNIX Server versions 6.x < 6.0.0.9.
      egrep(pattern:"ReflectionForSecureIT_6\.0\.0\.[0-8]", string:banner)
    ) security_note(port);
  }
  else if ("F-Secure SSH" >< banner) {
    if (
      #  F-Secure SSH Server for Windows versions 5.x < 5.3 build 35.
      egrep(pattern:"SSH-2\.0-5\.([0-2].*|3 Build ([0-2].*|3[0-4])) F-Secure SSH Windows", string:banner) ||
      #  F-Secure SSH Server for UNIX versions 3.x and 5.x < 5.0.8.
      egrep(pattern:"SSH-2\.0-(3\..*|5\.0\.[0-7]) F-Secure SSH", string:banner)
    ) security_note(port);
  }
}
