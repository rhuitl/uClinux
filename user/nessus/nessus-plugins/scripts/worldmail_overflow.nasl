#
# (C) Tenable Network Security
#


if (description) {
  script_id(20336);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-4267");
  script_bugtraq_id(15980);

  name["english"] = "Qualcomm WorldMail IMAPD Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

It is possible to execute code on the remote IMAP server.

Description :

The remote host is running a version of Qualcomm WorldMail's IMAP 
service that is prone to a buffer overflow vulnerability triggered
when processing too long command with '}'. An attacker can exploit
this flaw to execute arbitrary code subject to the privileges of
the affected application. 

See also :

http://seclists.org/lists/fulldisclosure/2005/Dec/1037.html
http://www.idefense.com/intelligence/vulnerabilities/display.php?id=359

Solution :

No solution at this time.

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for buffer overflow in Qualcomm WorldMail's IMAP service";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes", "global_settings.nasl");
  script_exclude_keys("imap/false_imap");
  script_require_ports("Services/imap", 143);

  exit(0);
}

include ("imap_func.inc");

port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);

#* OK  WorldMail 3 IMAP4 Server 6.1.22.0 ready
banner = get_imap_banner(port:port);
if (!banner || "WorldMail" >!< banner) exit(0);

if (egrep (pattern:"* OK  WorldMail [0-3] IMAP4 Server [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ready", string:banner))
{
 version = ereg_replace (pattern:".* OK  WorldMail [0-3] IMAP4 Server ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ready", string:banner, replace:"\1");
 version = split (version, sep:'.', keep:FALSE);

 version[0] = int(version[0]);
 version[1] = int(version[1]);
 version[2] = int(version[2]);
 version[3] = int(version[3]);

 if ( (version[0] < 6) ||
      ( (version[0] == 6) && (version[1] < 1) ) ||
      ( (version[0] == 6) && (version[1] == 1) && (version[2] < 22) ) ||
      ( (version[0] == 6) && (version[1] == 1) && (version[2] == 22) && (version[3] == 0) ) )
   security_hole (port);
}
