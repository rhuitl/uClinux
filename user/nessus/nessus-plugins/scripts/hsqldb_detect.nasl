#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host is running a database server.

Description :

The remote host is running HSQLDB, an open-source database written in
Java, and its database engine is listening on TCP port 9001 for
network server database connections using JDBC. 

See also :

http://hsqldb.org/

Risk factor : 

None";


if (description) {
  script_id(20065);
  script_version("$Revision: 1.3 $");

  script_name(english:"HSQLDB Server Detection");
  script_summary(english:"Detects an HSQLDB server");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports("Services/unknown", 9001);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(9001);
  if (!port) exit(0);
}
else port = 9001;
if (!get_tcp_port_state(port)) exit(0);


# Try to login.
soc = open_sock_tcp(port);
if (!soc) exit(0);

user = toupper("sa");                   # default username
pass = toupper("");                     # default password
db = "";
req = raw_string(
                                        # packet size, to be added later
  0x00, 0x01, 0x00, 0x07,               # ???, perhaps a version number
  0x00, 0x00, 0x00, 0x00,               # ???
  0x00, 0x00, 0x00, 0x00,               # ???
  0x00, 0x00, 0x00, strlen(user), user, # user
  0x00, 0x00, 0x00, strlen(pass), pass, # pass
  0x00, 0x00, 0x00, strlen(db), db,     # database name
  0x00, 0x00, 0x00, 0x00                # ???
);
req = raw_string(
  0x00, 0x00, 0x00, (strlen(req)+4),    # packet size, as promised
  req
);

send(socket:soc, data:req);


# Read the response.
res = recv(socket:soc, length:64);
if (res == NULL) exit(0);


# If it looks like an HSQLDB server because...
if (
  # we got in or ...
  (
    strlen(res) == 20 && 
    raw_string(
      0x00, 0x00, 0x00, 0x14, 
      0x00, 0x00, 0x00, 0x01, 
      0x00, 0x00, 0x00, 0x00
    ) >< res
  ) ||
  # the user name is invalid or ...
  string("User not found: ", user) >< res ||
  # the password is invalid or ...
  "Access is denied" >< res ||
  # the DB is invalid
  string("Database does not exists in statement [", db, "]") >< res
) {
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"hsqldb");

  if (
    strlen(res) == 20 && 
    raw_string(
      0x00, 0x00, 0x00, 0x14, 
      0x00, 0x00, 0x00, 0x01, 
      0x00, 0x00, 0x00, 0x00
    ) >< res
  ) {
    desc = str_replace(
      string:desc,
      find:"See also :",
      replace:string(
        "In addition, it was possible to log in with the username '", user, "'\n",
        "and password '", pass, "'.\n",
        "\n",
        "Solution :\n",
        "\n",
        "Change the username and/or password or restrict access to this port.\n",
        "\n",
        "See also :"
      )
    );
    desc = str_replace(
      string:desc,
      find:"None",
      replace:string(
        "Medium / CVSS Base Score : 5\n",
        "(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)"
      )
    );
    security_warning(port:port, data:desc);
  }
  else {
    security_note(port:port, data:desc);
  }
}
