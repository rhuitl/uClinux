#!/bin/sh

/usr/sbin/conntrackd -c # commit the cache
/usr/sbin/conntrackd -f # flush the caches
/usr/sbin/conntrackd -R # resync with kernel conntrack table
