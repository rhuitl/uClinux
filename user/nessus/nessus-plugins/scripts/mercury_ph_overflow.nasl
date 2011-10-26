#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote ph service is affected by a buffer overflow vulnerability. 

Description :

The remote host is running the Mercury Mail Transport System, a free
suite of server products for Windows and Netware associated with
Pegasus Mail. 

The remote installation of Mercury includes a ph server that is
vulnerable to buffer overflow attacks.  By leveraging this issue, an
unauthenticated remote attacker is able to crash the remote service
and possibly execute arbitrary code remotely. 

See also :

http://www.milw0rm.com/id.php?id=1375
http://www.pmail.com/newsflash.htm#whfix

Solution :

Install the Jan 2006 Mercury/32 Security patches for MercuryW and
MercuryH from http://www.pmail.com/patches.htm. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20812);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-4411");
  script_bugtraq_id(16396);

  script_name(english:"Mercury ph Server Buffer Overflow Vulnerability");
  script_summary(english:"Checks for a buffer overflow vulnerability in Mercury ph Server");

  script_description(english:desc);

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service2.nasl");
  script_require_keys("Services/ph", 105);

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/ph");
if (!port) port = 105;
if (!get_tcp_port_state(port)) exit(0);


# Open a connection.
soc = open_sock_tcp(port);
if (soc) {
  # If safe checks are enabled...
  if (safe_checks() || report_paranoia < 2 ) {
    # Try to pull out the version number from the HELP.
    send(socket:soc, data:string("HELP\r\n"));
    res = recv(socket:soc, length:1024);
    if (res == NULL) exit(0);

    # nb: the banner with the patch applied reports "Mercury Simple PH Server v4.1 beta 6".
    if (egrep(pattern:" Mercury Simple PH Server v([0-3]\.|4\.0(0|1($|[ab])))", string:res)) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus has determined the flaw exists with the application\n",
        "simply by looking at the version in its banner.\n"
      );
      security_hole(port:port, data:report);
    }
  }
  # Otherwise...
  else {
    # Try to crash the service.
    send(socket:soc, data:string(crap(1000), "\r\n"));
    res = recv(socket:soc, length:256);

    # Try to reconnect if we didn't get anything back.
    if (res == NULL) {
      soc2 = open_sock_tcp(port);
      if (soc2) close(soc2);
      else {
        security_hole(port);
        exit(0);
      }
    }
  }

  close(soc);
}
