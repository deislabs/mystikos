while sudo lsof /var/lib/dpkg/lock-frontend | grep dpkg; do sleep 3; done
