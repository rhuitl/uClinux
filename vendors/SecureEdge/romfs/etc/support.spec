# Indicates which files should/shouldn't be included in the Technical Support Report
# First matching rule takes precedence
exclude ipsec.secrets ipsec.conf
include pap-secrets chap-secrets
  replace [^ ]* [^ ]* ([^ ]*) .*
include config
  replace mgmt_password (.*)
  replace c_pswd (.*)
include snmpd.conf
  replace r[ow]community (.*)
include options.*
  replace radius-secret (.*)
  replace tacacs-secret (.*)
include ddns*.conf
  replace user=.*:(.*)
include bpalogin.conf
  replace password (.*)
include start
  replace dhcpcd.*-h ([^-][^ ]*).*-I ([^ ]*).*
include gconfig
  replace password=(.*)
  replace .*community=(.*)
exclude ssh_host_*
exclude id_*
exclude identity identity.pub
exclude *.pem
include wireless*
  replace wep_key_.* (.*)
  replace wpa_psk (.*)
  replace auth_server_shared_secret (.*)
include hostapd*.conf
  replace auth_server_shared_secret=(.*)
  replace acct_server_shared_secret=(.*)
include smbpasswd
  replace [^:]*:[^:]*:([^:]*):([^:]*).*
