#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host contains an application that is vulnerable to remote
buffer overflow attacks. 

Description :

The version of eIQnetworks Enterprise Security Analyzer, Network
Security Analyzer, or one of its OEM versions installed on the remote
host is affected by multiple stack-based buffer overflows in its
Syslog Service.  Using a long argument to any of several commands, an
unauthenticated remote attacker may be able to leverage this issue to
execute arbitrary code on the affected host with LOCAL SYSTEM
privileges. 

See also :

http://www.tippingpoint.com/security/advisories/TSRT-06-03.html
http://www.securityfocus.com/archive/1/441200/30/90/threaded
http://www.eiqnetworks.com/support/Security_Advisory.pdf

Solution :

Upgrade to Enterprise Security Analyzer 2.1.14 / Network Security
Analyzer 4.5.4 / OEM software 4.5.4 or later

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22127);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-3838");
  script_bugtraq_id(19165, 19167);
  if (defined_func("script_xref"))
  {
    script_xref(name:"OSVDB", value:"27525");
    script_xref(name:"OSVDB", value:"27527");
  }

  script_name(english:"eIQnetworks Enterprise Security Analyzer Syslog Server Multiple Buffer Overflow Vulnerabilities");
  script_summary(english:"Tries to crash ESA Syslog Server with a long argument to DELETERDEPDEVICE command");
 
  script_description(english:desc);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("esa_syslog_detect.nasl");
  script_require_ports("Services/esa_syslog", 10617);

  exit(0);
}


port = get_kb_item("Services/esa_syslog");
if (!port) port = 10617;
if (!get_port_state(port)) exit(0);


# If safe checks are enabled...
if (safe_checks())
{
  ver = get_kb_item("ESA/Syslog/"+port+"/Version");
  if (ver && "~" >< ver)
  {
    date = strstr(ver, "~") - "~";
    d = split(date, sep:'/', keep:FALSE);
    if (
      int(d[2]) < 2006 ||
      (
        int(d[2]) == 2006 &&
        (
          int(d[0]) < 7 ||
          (int(d[0]) == 7 && int(d[1]) < 26)
        )
      )
    )
    {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus has used the build date, ", date, ", of the software on the\n",
        "remote host to determine that it is vulnerable to these issues.\n"
      );
      security_warning(port:port, data:report);
    }
  }
}
# Otherwise...
else
{
  soc = open_sock_tcp(port);
  if (soc) 
  {
    # Try to exploit one of the flaws.
    #
    # nb: the form taken by the exploit depends on the command used.
    send(socket:soc, data:string("DELTAINTERVAL:", crap(3200)));
    res = recv(socket:soc, length:64);
    close(soc);

    # If we didn't get a response...
    if (isnull(res)) 
    {
      # Try to reconnect.
      soc2 = open_sock_tcp(port);
      if (!soc2) security_warning(port);
      else close(soc2);
    }
  }
}
