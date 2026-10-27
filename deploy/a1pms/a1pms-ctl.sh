#!/bin/sh
# ricproof: restart the A1PMS container and return once both RICs are AVAILABLE.
# Used as RICPROOF_A1PMS_RESTART_CMD ("a1pms-ctl.sh restart") and
# RICPROOF_A1PMS_STOP_CMD ("a1pms-ctl.sh stop").
URL=${RICPROOF_A1PMS_URL:-http://localhost:8081}
case "$1" in
  stop)    docker stop ricproof-a1pms > /dev/null ;;
  start)
    docker start ricproof-a1pms > /dev/null
    for i in $(seq 1 120); do sleep 1; curl -s -o /dev/null "$URL/a1-policy/v2/status" && break; done
    for i in $(seq 1 120); do sleep 1; n=$(curl -s "$URL/a1-policy/v2/rics" | grep -o '"state":"AVAILABLE"' | wc -l); [ "$n" -ge 2 ] && break; done ;;
  restart) "$0" stop; "$0" start ;;
esac
