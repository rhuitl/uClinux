#!/usr/bin/tclsh
package require Tclx

proc run_close {f} {
	if {[catch {
		close $f
	} error]} {
		if {[lindex $::errorCode 0] eq "CHILDSTATUS"} {
			set status [lindex $::errorCode 2]
			if {$status} {
				puts stderr "error: $error"
				puts stderr "status: $status"
				exit 1
			}
		} else {
			puts $error
		}
	}
}

proc run {args} {
	if {[catch {
		eval exec $args
	} error]} {
		if {[lindex $::errorCode 0] eq "CHILDSTATUS"} {
			set status [lindex $::errorCode 2]
			if {$status} {
				puts stderr "failed: $args"
				puts stderr "error: $error"
				puts stderr "status: $status"
				exit 1
			}
		} else {
			puts $error
		}
	}
}

proc compress {} {
	run gzip -c -9 image.bin > imagez.bin
	run mv imagez.bin image.bin
}

proc put_cksum {} {
	run $::env(ROOTDIR)/tools/cksum -b -o 2 image.bin >> image.bin
}

proc put_version {} {
	run printf {\0%s\0%s\0%s} $::env(TESTVERSIONPKG) $::env(VENDOR) $::env(PRODUCT) >> image.bin
}

proc put_cgi {f val} {
	puts -nonewline $f $val
}
proc put_cgi_var {f boundary name val} {
	put_cgi $f "\r\n--$boundary\r\n"
	put_cgi $f "Content-Disposition: form-data; name=\"$name\"\r\n"
	put_cgi $f "\r\n"
	put_cgi $f "$val"
}

proc run_cgi {{opt ""}} {
	set ::cgi_success 0
	signal trap SIGUSR1 {set ::cgi_success 1}
	set boundary "---------------------------16102434721271555362696379123"
	set ::env(REQUEST_METHOD) "POST"
	set ::env(CONTENT_TYPE) "multipart/form-data; boundary=$boundary"
	set ::env(CONTENT_LENGTH) "1"
	set f [open "|./netflash cgi://Fn0rD_data,params,flash_region" "w"]
	fconfigure $f -translation binary -encoding binary
	set fimage [open "image.bin" "r"]
	fconfigure $fimage -translation binary -encoding binary
	put_cgi_var $f $boundary "Fn0rD_data" [read $fimage]
	close $fimage
	put_cgi_var $f $boundary "params" $opt
	put_cgi_var $f $boundary "flash_region" "firmware"
	put_cgi $f "\r\n--$boundary--"
	run_close $f
	signal default SIGUSR1
}

proc run_netflash {{opt ""}} {
	if {$opt != ""} {
		run ./netflash $opt -abkt -R flash.bin image.bin >@stdout
		run ./netflash $opt -abk -R flash.bin image.bin >@stdout
		run_cgi "$opt -abk -R flash.bin"
	} else {
		run ./netflash -abkt -R flash.bin image.bin >@stdout
		run ./netflash -abk -R flash.bin image.bin >@stdout
		run_cgi "-abk -R flash.bin"
	}
}

proc run_cmp {filename} {
	run cmp -b $filename flash.bin >@stdout
}

set ::testindex 1
proc test {name {compress 0}} {
	puts "\n\nTest $::testindex: $name\n"
	incr ::testindex
	run cp raw.bin image.bin
}

run dd if=/dev/urandom of=raw.bin bs=512 count=1000

if {[info exists ::env(CONFIG_USER_NETFLASH_CRYPTO)]} {
	run openssl genrsa -out rsa.pem 2048 >@stdout
	run openssl rsa -in rsa.pem -pubout > $::env(PUBLIC_KEY_FILE)
}

test "Raw"
run_netflash -n
run_cmp raw.bin

# Warning: doremoveversion is still set, and it may incorrectly
# think this image has version info, causing test to fail.
test "Checksum"
put_cksum
run_netflash -iH
run_cmp raw.bin

test "Version"
put_version
put_cksum
run_netflash
run_cmp raw.bin

if {[info exists ::env(CONFIG_USER_NETFLASH_CRYPTO)]} {
	test "Crypto"
	put_version
	run ./cryptimage -v -k rsa.pem -f image.bin >@stdout
	run cp image.bin signed.bin
	put_version
	put_cksum
	run_netflash
	run_cmp signed.bin
}

if {[info exists ::env(CONFIG_USER_NETFLASH_SHA256)]} {
	test "SHA256"
	put_version
	run cat image.bin | ./sha256sum -b >> image.bin
	run cp image.bin signed.bin
	put_version
	put_cksum
	run_netflash
	run_cmp signed.bin
}

test "Raw/compress"
compress
run_netflash -nz
run_cmp raw.bin

# Warning: doremoveversion is still set, and it may incorrectly
# think this image has version info, causing test to fail.
test "Checksum/compress"
compress
put_cksum
run_netflash -iHz
run_cmp raw.bin

test "Version/compress"
compress
put_version
put_cksum
run_netflash -z
run_cmp raw.bin

if {[info exists ::env(CONFIG_USER_NETFLASH_CRYPTO)]} {
	test "Crypto/compress"
	compress
	put_version
	run ./cryptimage -v -k rsa.pem -f image.bin >@stdout
	run cp image.bin signed.bin
	put_version
	put_cksum
	run_netflash -z
	# Note: signature is currently stripped, which seems wrong
	# to me... not sure if anything uses this mode yet
	run_cmp raw.bin
}

if {[info exists ::env(CONFIG_USER_NETFLASH_SHA256)]} {
	test "SHA256/compress"
	compress
	put_version
	run cat image.bin | ./sha256sum -b >> image.bin
	run cp image.bin signed.bin
	put_version
	put_cksum
	run_netflash -z
	run_cmp signed.bin
}

