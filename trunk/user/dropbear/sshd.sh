#!/bin/sh

dir_storage="/etc/storage/dropbear"
rsa_key="$dir_storage/rsa_host_key"
dss_key="$dir_storage/dss_host_key"
ecdsa_key="$dir_storage/ecdsa_host_key"
ed25519_key="$dir_storage/ed25519_host_key"
extra_args="$dir_storage/extra_args"

func_createkeys()
{
	rm -f "$rsa_key"
	rm -f "$dss_key"
	rm -f "$ecdsa_key"
	rm -f "$ed25519_key"

	[ ! -d "$dir_storage" ] && mkdir -p -m 755 $dir_storage
	/usr/bin/dropbearkey -t rsa -f "$rsa_key"
	/usr/bin/dropbearkey -t dss -f "$dss_key"
	/usr/bin/dropbearkey -t ecdsa -f "$ecdsa_key"
	/usr/bin/dropbearkey -t ed25519 -f "$ed25519_key"
	chmod 600 "$rsa_key"
	chmod 600 "$dss_key"
	chmod 600 "$ecdsa_key"
	chmod 600 "$ed25519_key"
}

func_get_extra_args()
{
    [ -f $extra_args ] || echo "-p 22" > $extra_args
    cat $extra_args
}

func_start()
{
	args=$(func_get_extra_args)

	[ ! -d "$dir_storage" ] && mkdir -p -m 755 $dir_storage

	old_pattern="/etc/storage/dropbear_"
	for i in rsa_host_key dss_host_key ecdsa_host_key ; do
		[ -f "${old_pattern}_${i}" ] && mv -n "${old_pattern}_${i}" "$dir_storage/${i}"
	done

	if [ ! -f "$rsa_key" ] || [ ! -f "$dss_key" ] ; then
		func_createkeys
	fi

	if [ ! -f "$ecdsa_key" ]; then
		/usr/bin/dropbearkey -t ecdsa -f "$ecdsa_key"
		chmod 600 "$ecdsa_key"
	fi

	if [ ! -f "$ed25519_key" ]; then
		/usr/bin/dropbearkey -t ed25519 -f "$ed25519_key"
		chmod 600 "$ed25519_key"
	fi

	if [ -n "$1" ]; then
		args="$1 $args"
	fi

	echo $args | xargs /usr/sbin/dropbear
}

func_stop()
{
	killall -q dropbear
}

case "$1" in
start)
	func_start $2
	;;
stop)
	func_stop
	;;
newkeys)
	func_createkeys
	;;
*)
	echo "Usage: $0 {start|stop|newkeys}"
	exit 1
	;;
esac

exit 0
