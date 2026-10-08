#!/bin/bash
# makes the video segments (once) and starts the mail server on gw-b
cd ~/ipsecscope/testbed/traffic || exit 1
docker cp mail.py gw-a:/tmp/mail.py
docker cp mail.py gw-b:/tmp/mail.py
docker exec gw-b bash -c 'mkdir -p /srv/www/video && cd /srv/www/video && [ -f low_000.ts ] || ffmpeg -loglevel error -y -f lavfi -i testsrc2=size=640x360:rate=25 -f lavfi -i sine=frequency=440 -t 60 -c:v libx264 -preset ultrafast -b:v 800k -maxrate 800k -bufsize 1600k -g 50 -sc_threshold 0 -c:a aac -b:a 64k -f segment -segment_format mpegts -segment_time 2 -reset_timestamps 1 low_%03d.ts'
docker exec gw-b bash -c 'cd /srv/www/video && [ -f high_000.ts ] || ffmpeg -loglevel error -y -f lavfi -i testsrc2=size=1280x720:rate=25 -f lavfi -i sine=frequency=440 -t 60 -c:v libx264 -preset ultrafast -b:v 2500k -maxrate 2500k -bufsize 5000k -g 50 -sc_threshold 0 -c:a aac -b:a 128k -f segment -segment_format mpegts -segment_time 2 -reset_timestamps 1 high_%03d.ts'
docker exec -d gw-b python3 /tmp/mail.py server
echo "video segments ready, mail server started on gw-b"
docker exec gw-b bash -c 'ls /srv/www/video | wc -l; du -sh /srv/www/video'
