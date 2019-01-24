#!/bin/bash
#
#
# VPS_open.sh
# Open the Payload
#
# GitHub: https://github.com/rippledj/VPS_deploy_wordpress
# Author: Joseph Lee
# Email: joseph@ripplesoftware.ca
#
# Load a list of directories that will require special permissions
echo "[Opening permisssions for development access...]"
while read -r -a dirperm
do
  # Eliminate all comment lines
  if [[ ${dirperm[0]:0:1} != "#" && ! -z "${dirperm[0]}" ]]; then
    # If file is specified, file all files and chmod
    if [ ${dirperm[0]} = "<dir>" ]; then
      if [ ${dirperm[1]} = "-R" ]; then
        echo "Directory Recursive Mode: chmod -R ${dirperm[2]} ${dirperm[3]}"
        find ${dirperm[3]} -type d -exec chmod ${dirperm[2]} -- {} +
      else
        echo "Directory Mode: chmod ${dirperm[1]} ${dirperm[2]}"
        chmod ${dirperm[1]} ${dirperm[2]}
      fi
    fi
    # If file is specified, file all files and chmod
    if [ ${dirperm[0]} = "<file>" ]; then
      if [ ${dirperm[1]} = "-R" ]; then
        echo "File Recursive Mode: chmod -R ${dirperm[2]} ${dirperm[3]}"
        find ${dirperm[3]} -type f -exec chmod ${dirperm[2]} -- {} +
      else
        echo "File Mode: chmod ${dirperm[1]} ${dirperm[2]}"
        chmod ${dirperm[1]} ${dirperm[2]}
      fi
    fi
    # If SELinux dir specified open directory for SELinux read
    if [ ${dirperm[0]} = "<se-dir-read>" ]; then
      if [ ${dirperm[1]} = "-R" ]; then
        echo "SE Directory Read Recursive Mode: ${dirperm[2]}"
        find ${dirperm[2]} -type d -exec chcon -t httpd_sys_content_t ${dirperm[2]} -R -- {} +
      else
        echo "SE Directory Read Mode: ${dirperm[1]}"
        chcon -t httpd_sys_content_t ${dirperm[1]}
      fi
    fi
    # If SELinux dir specified open directory for SELinux read/write
    if [ ${dirperm[0]} = "<se-dir-read-write>" ]; then
      if [ ${dirperm[1]} = "-R" ]; then
        echo "SE Directory Read/Write Recursive Mode: ${dirperm[2]}"
        find ${dirperm[2]} -type d -exec chcon -t httpd_sys_rw_content_t ${dirperm[2]} -R -- {} +
      else
        echo "SE Directory Read/Write Mode: ${dirperm[1]}"
        chcon -t httpd_sys_rw_content_t ${dirperm[1]}
      fi
    fi
  fi
done < payloads/site_permissions_open
echo "[Permisssions opened for development access...]"
