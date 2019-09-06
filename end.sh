kill $(ps aux | grep mperf | grep -v grep | awk '{print $2}')
kill $(ps aux | grep raw_tcp | grep -v grep | awk '{print $2}')
kill $(ps aux | grep tcpdump | grep -v grep | awk '{print $2}')

