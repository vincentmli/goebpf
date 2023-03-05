#! /bin/sh
### BEGIN INIT INFO
# Provides:          xdp_fw 
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     5
# Default-Stop:      0 1 6
# Description: Starts xdp firewall configuration
# short-description: xdp firewall configuration
### END INIT INFO

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/etc/firehol
NAME=xdp_fw
DESC="xdp firewall"
SCRIPTNAME=/etc/init.d/$NAME

test -x /etc/firehol/xdp_fw || exit 0

# load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# include lsb functions
. /lib/lsb/init-functions

do_start () {

	/etc/firehol/xdp_fw -attach -port 8080 > /dev/null 2>&1 || return 1
}

do_stop () {
	/etc/firehol/xdp_fw_stop.sh
}

COMMAND="$1"
[ "$COMMAND" ] && shift

case "$COMMAND" in
	start)
		[ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
		do_start 
		case "$?" in
			0) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
			1) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
			4) [ "$VERBOSE" != no ] && { log_progress_msg "disabled, see /etc/default/firehol" ; log_end_msg 255 ; } ;;
		esac
	;;

	stop)
		[ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
		do_stop
		case "$?" in
			0) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
			1) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
		esac
	;;

	*)
	echo "Usage: $SCRIPTNAME {start|stop} [<args>]" >&2
	exit 3
	;;
esac

:

