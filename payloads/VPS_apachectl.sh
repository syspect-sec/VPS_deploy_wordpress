#!/bin/bash
#
#
# VPS_apachectl.sh
# Restart Apache
#
# GitHub: https://github.com/rippledj/VPS_deploy_wordpress
# Author: Joseph Lee
# Email: joseph@ripplesoftware.ca
#
# Apachectl Script accepts the command then starts or restarts apache
if [ $1 = "restart" ]; then
  # Restart Apache
  echo "[Restarting Apache...]"
  systemctl restart httpd
  # Show status of Apache
  systemctl status httpd
  echo "[Apache restarted...]"
elif [ $1 = "start" ]; then
  # Restart Apache
  echo "[Starting Apache...]"
  systemctl start httpd
  # Show status of Apache
  systemctl status httpd
  echo "[Apache started...]"
fi
