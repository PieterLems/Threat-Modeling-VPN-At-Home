#!/bin/sh
#
# This is just a wrapper around Django's manage.py that
# calls it as app user, ensuring that all generated files
# have proper ownership.
#

sudo -u vpnathome /usr/lib/vpnathome/venv/bin/manage.py $@
