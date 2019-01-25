#!/bin/bash
#
#
# VPS_remote_backup.sh
# Remote Backup Script
#
# GitHub: https://github.com/rippledj/VPS_deploy_wordpress
# Author: Joseph Lee
# Email: joseph@ripplesoftware.ca
#
# Update the live site branch of GitHub repository
#
echo "[Pushing changes to GitHub repository...]"
if [ -s payloads/id_rsa_github ]
then
    echo "[Starting to process GitHub repository update...]"
    # Make a ssh directory and set permissions
    mkdir /root/.ssh
    # Add the ssh identity file to root to configure connection to github
    echo "[Adding identify files to root...]"
    /bin/cp payloads/ssh_identity_file /root/.ssh/
    mv /root/.ssh/ssh_identity_file /root/.ssh/config
    chmod 0400 /root/.ssh/config
    echo "[Adding GitHub as known host to root...]"
    # Add github.com to the known_hosts file
    ssh-keyscan -H github.com >> /root/.ssh/known_hosts
    # Copy the id_rsa_github and id_rsa_github.pub to /root/.ssh directory
    echo "[Moving GitHub SSH keys to root...]"
    /bin/cp payloads/id_rsa_github /root/.ssh
    /bin/cp payloads/id_rsa_github.pub /root/.ssh
    # Modify permissions
    chmod 0400 /root/.ssh/id_rsa_github
    chmod 0400 /root/.ssh/id_rsa_github.pub
    # Copy the id_rsa_github to ssh-agent
    echo "[Adding GitHub SSH keys to root ssh agent...]"
    eval `ssh-agent -s`
    ssh-add /root/.ssh/id_rsa_github
    # For each repository listed in githubuser file
    while read -r -a githubuser
    do
      # Eliminate comments
      if [[ ${githubuser[0]:0:1} != "#" && ! -z "${githubuser[0]}" ]]; then
        # Clone the repo for the site to be installed
        echo "[Adding changes to GitHub repository...]"
        cd /var/www/html/${githubuser[0]}
        git add -A
        echo "[Commiting changes to GitHub repository...]"
        git commit -m "Auto commit from server on \$(date +\%m_\%d_\%Y)"
        echo "[Pushing commits to GitHub repository...]"
        git push origin live_branch
        # Remove the ssh-agent deamon
        eval `ssh-agent -k`
        echo "[ssh-agent process killed...]"
        # Set permissions files for host domain
        echo "[Re-writing ownership...]"
        chown -R apache:apache /var/www/html/${githubuser[0]}
        echo "[Finished re-writing ownership...]"
      fi
    done < payloads/github_userdata
fi
echo "[VPS_deploy has finished pushing changes to GitHub repository...]"
#
# Push the database backup to remote server
#
echo "[Starting to process remote database backup...]"
# Make a ssh directory and set permissions
mkdir /root/.ssh
# Add the ssh identity file to root to configure connection to github
echo "[Adding identify files to root...]"
/bin/cp payloads/ssh_identity_file /root/.ssh/
mv /root/.ssh/ssh_identity_file /root/.ssh/config
chmod 0400 /root/.ssh/config
echo "[Adding remote backup server as known host to root...]"
if [ -s payloads/remote_serverdata ]
then
  # Read the remote_backup_IP
  while read -r -a remote_server
  do
    # Add remote backup server to the known_hosts file
    ssh-keyscan -H ${remote_server} >> /root/.ssh/known_hosts
  done < payloads/remote_serverdata
fi
# Copy the id_rsa_remote and id_rsa_remote.pub to /root/.ssh directory
echo "[Moving remote server SSH keys to root...]"
/bin/cp payloads/id_rsa_remote /root/.ssh
/bin/cp payloads/id_rsa_remote.pub /root/.ssh
# Modify permissions
chmod 0400 /root/.ssh/id_rsa_remote
chmod 0400 /root/.ssh/id_rsa_remote.pub
# Copy the id_rsa_remote to ssh-agent
echo "[Adding remote server SSH keys to root ssh agent...]"
eval `ssh-agent -s`
ssh-add /root/.ssh/id_rsa_remote
# Move the SQL backup file to the remote servers
if [ -s payloads/id_rsa_remote ]
then
  # For each server listed in remote_serverdata
  while read -r -a remote_server
  do
    # Copy SQL backup to the known hosts file
    scp /home/<non_root_username>/<github_reponame>_database_backup.sql backup@${remote_server}:./
  done < payloads/remote_serverdata
fi
#
# Clean up
#
# Clear the command line history
echo "[Removing command line history...]"
history -c
echo "[Command line history removed...]"
echo "[Removing SSH directory...]"
rm -rf /root/.ssh
echo "[SSH directory removed...]"
# Send a success exit code
exit 0
