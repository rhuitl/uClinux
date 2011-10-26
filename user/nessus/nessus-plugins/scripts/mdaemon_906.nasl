#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22256);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-4364");
  script_bugtraq_id(19651);
  script_xref(name:"OSVDB", value:"28125");

  script_name(english:"MDaemon < 9.0.6 POP3 Server Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version of MDaemon POP3 Server");

  desc = "
Synopsis :

The remote POP3 server is affected by multiple buffer overflow flaws. 

Description :

The remote host is running Alt-N MDaemon, a mail server for Windows. 

According to its banner, the POP3 server bundled with the version of
MDaemon on the remote host has two buffer overflows that can be
triggered with long arguments to the 'USER' and 'APOP' commands.  By
exploiting these issues, a remote, unauthenticated user can reportedly
crash the affected service or run arbitrary code with LOCAL SYSTEM
privileges. 

See also :

http://www.infigo.hr/en/in_focus/advisories/INFIGO-2006-08-04
http://www.securityfocus.com/archive/1/444015/30/0/threaded
http://files.altn.com/MDaemon/Release/RelNotes_en.txt

Solution :

Upgrade to MDaemon version 9.0.6 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}


include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Do a banner check.
banner = get_pop3_banner(port:port);
if (
  banner &&
  " POP MDaemon " >< banner && 
  egrep(pattern:" POP MDaemon( ready using UNREGISTERED SOFTWARE)? ([0-8]\.|9\.0\.[0-5][^0-9])", string:banner)
) security_note(port);
