ps aux | egrep -i '(cloud-hypervisor|chv-lambda-server)' | awk '{print $2}' | xargs kill -9
rm -rf /run/chv-lambda/*
