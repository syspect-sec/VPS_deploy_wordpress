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
# Prepare SSH to load keys
#
echo "[Creating SSH directory...]"
mkdir /root/.ssh
# Add the ssh identity file to root to configure connection to GitHub
echo "[Adding identify files to root...]"
cp /root/VPS_deploy/payloads/ssh_identity_file /root/.ssh/
mv /root/.ssh/ssh_identity_file /root/.ssh/config
chmod 0400 /root/.ssh/config
#
# Perform GitHub backup actions
#
echo "[Starting to process GitHub repository update...]"
if [ -s /root/VPS_deploy/payloads/id_rsa_github ]
then
    echo "[Starting to process GitHub repository update...]"
    echo "[Adding GitHub as known host to root...]"
    # Add github.com to the known_hosts file
    ssh-keyscan -H github.com >> /root/.ssh/known_hosts
    # Copy the GitHub SSH keys to /root/.ssh directory
    echo "[Moving GitHub SSH keys to root...]"
    cp /root/VPS_deploy/payloads/id_rsa_github /root/.ssh
    cp /root/VPS_deploy/payloads/id_rsa_github.pub /root/.ssh
    # Modify permissions
    chmod 0400 /root/.ssh/id_rsa_github
    chmod 0400 /root/.ssh/id_rsa_github.pub
    # Copy the id_rsa_github to ssh-agent
    echo "[Adding GitHub SSH keys to root ssh agent...]"
    eval `ssh-agent -s`
    ssh-add /root/.ssh/id_rsa_github
    #
    # Push the live site to the GitHub repository 'live' branch
    #
    cd /var/www/html/rsrc_wordpress
    # Create a branch for current state
    git branch $(date '+%Y-%m-%d')
    # Add the changes to the live branch
    git add -A
    echo "[Commiting changes to GitHub repository...]"
    git commit -m "Auto commit from server"
    echo "[Pushing commits to GitHub repository...]"
    git push origin master
    # Set permissions files for host domain
    echo "[Re-writing ownership...]"
    chown -R apache:apache /var/www/html/rsrc_wordpress
    echo "[Finished re-writing ownership...]"
fi
echo "[VPS_deploy has finished pushing changes to GitHub repository...]"
#
# Clean up
#
# Remove the ssh-agent deamon
eval `ssh-agent -k`
echo "[ssh-agent process killed...]"
# Clear the command line history
echo "[Removing command line history...]"
history -c
rm -rf /root/.bash_history
echo "[Command line history removed...]"
echo "[Removing SSH directory...]"
rm -rf /root/.ssh
echo "[SSH directory removed...]"
# Send a success exit code
exit 0
