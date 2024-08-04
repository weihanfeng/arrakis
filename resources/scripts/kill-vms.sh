ps aux | grep -i cloud-hypervisor | awk '{print $2}' | xargs kill -9
