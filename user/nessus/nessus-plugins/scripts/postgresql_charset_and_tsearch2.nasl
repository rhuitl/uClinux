#
# (C) Tenable Network Security
#


if (description) {
  script_id(18202);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1409", "CVE-2005-1410");
  script_bugtraq_id(13475, 13476);

  name["english"] = "PostgreSQL Character Conversion and Tsearch2 Module Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote database server is affected by multiple vulnerabilities. 

Description :

According to its banner, the version of PostgreSQL installed on the
remote host may suffer from the following vulnerabilities :

  - Character Conversion Vulnerability
    Unprivileged users can call functions supporting client-
    server character set conversion from SQL commands even
    though those functions do not validate their arguments.

  - tsearch2 Vulnerability
    If installed, the 'contrib/tsearch2' module permits users
    to at a minimum crash the backend because it misdeclares 
    several functions as returning type 'internal' when in 
    fact they do not have any 'internal' argument.

See also: 

http://www.postgresql.org/about/news.315
http://developer.postgresql.org/docs/postgres/release-8-0-3.html

Solution : 

Implement the changes described in the PostgreSQL advisory.

Risk factor : 

Medium / CVSS Base Score : 4
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for character conversion and tsearch2 module vulnerabilities in PostgreSQL";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/postgres", 5432);

  exit(0);
}


port = get_kb_item("Services/postgres");
if (!port) port = 5432;
if (!get_port_state(port)) exit(0);


# Request the database 'template1' as the user 'postgres' or 'pgsql'.
zero = raw_string(0x00);
user[0] = "postgres";
user[1] = "pgsql";

for (i=0; i<2; i=i+1) {
  soc = open_sock_tcp(port);
  if(!soc) exit(0);

  usr = user[i];
  len = 224 - strlen(usr);
  req = raw_string(
          0x00, 0x00, 0x01, 0x28, 0x00, 0x02,
          0x00, 0x00, 0x74, 0x65, 0x6D, 0x70, 0x6C, 0x61,
          0x74, 0x65, 0x31
        ) + 
        crap(data:zero, length:55) +
        usr +
        crap(data:zero, length:len);

  send(socket:soc, data:req);
  res = recv(socket:soc, length:5);
  res2 = recv(socket:soc, length:1024);
  if ((res[0]=="R") && (strlen(res2) == 10)) {
    req = raw_string(0x51) + 
          "select version();" + 
    	  raw_string(0x00);
    send(socket:soc, data:req);
    res = recv(socket:soc, length:65535);
    res = strstr(res, "PostgreSQL");

    if (res != NULL) {
      for (i=0; i<strlen(res); i++) {
        if (ord(res[i]) == 0) break;
      }
      res = substr(res, 0, i-1);
      # nb: the vulnerabilities affect 7.3.0 - 8.0.2.
      if (ereg(string:res, pattern:"PostgreSQL (7\.[34]|8\.0\.[0-2][^0-9])")){
     	security_warning(port);
      }
    }
    else if ("ERROR: function version()" >< res && report_paranoia > 1) security_warning(port);
    exit(0);
  }
}
