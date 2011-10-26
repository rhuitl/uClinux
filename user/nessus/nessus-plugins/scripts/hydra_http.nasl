#TRUSTED ac82bd26bdde9065d9aca7fd92f1afcff5e7f6b8567fe3788c65a6be4870a9b1ee68426d6e2a61d190bb8ef4fa7797b419e38c2455a203788073bd3804543ea9b02cd05adf6c7eaf62aa26c513cb3048ccf32b418c226b4c2dde9158d6d5d7b332136c63cc4e864e617c1937e8bcd4e02981267e401e3c846d640cd14ca91e1899e94445997dcc99147da8af583f26ac88b5e17537bb52cec603ec50152d5c428022c096ee58c77a5214cd7a97a132f2bf9c15e17e190142678e82500e5d07dda9a6c0ea13ef4bbc4436edeb6330c39ddcb9cd05008576b013d3e677755d54b447bebf1909acfe53a8544f61e43b468b5a7cb893bad229ab1e6d559287109b90889ea498e4900665538bb681d81f3bfb6d30d17a097bb7d596f49cd8fbbe0e43a90d2ed198c7ef266383f5e1864c206f56365fa6915de565494726beb9c078e9847ad1cb12815bcd0000a3ca608a6e39a087be7a06c5f155d6587ba073a19a29fbb96da1dfbc6f4a295cdbb33bc5d90a6a64357076b77d718ebedb4fc500e71908750d58b22f5f338afe33cca7784240e9181b81db3300e3edcacfca465c028ad86bb8d865ea16be1ce0cb7e23af1dfac869e00451e14097523380f42f940baab9d3f27afad2e0eaf3adaa5ca7edf4b860bb991a4d5121dcdf16133d5569f73d3013d6e8921062764a29a5dbd2c4995fdbd41bbfd579e7a46ad2dc7486fbf69f
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15873);
 script_version ("1.3");
 script_xref(name: "OWASP", value: "OWASP-AUTHN-004");
 script_xref(name: "OWASP", value: "OWASP-AUTHN-006");
 script_xref(name: "OWASP", value: "OWASP-AUTHN-010");
 name["english"] = "Hydra: HTTP";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find HTTP passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force HTTP authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 
 script_add_preference(name: "Web page :", value: "", type: "entry");

 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/www", 80);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0);
if ( get_kb_item("Services/www/" + port + "/broken") ) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;
argv[i++] = "-P"; argv[i++] = passwd;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "http";

opt = script_get_preference("Web page :");
if (! opt)
{
  v = get_kb_list('www/'+port+'/content/auth_required');
  if (!isnull(v)) opt = v[0];
}
if (! opt) exit(0);
# Check that web page is forbidden
soc = http_open_socket(port);
if (! soc) exit(0);
send(socket: soc, data: 
 strcat('GET ', opt, ' HTTP/1.1\r\nHost: ', get_host_name(), '\r\n\r\n'));
r = recv_line(socket: soc, length: 512);
http_close_socket(soc);
if (r !~ "^HTTP/1\.[01] +403 ") exit(0);
#
argv[i++] = opt;

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/http/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following HTTP accounts:\n' + report);
