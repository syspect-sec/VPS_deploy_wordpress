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
cp /root/payloads/ssh_identity_file /root/.ssh/
mv /root/.ssh/ssh_identity_file /root/.ssh/config
chmod 0400 /root/.ssh/config
#
# Perform GitHub backup actions
#
echo "[Starting to process GitHub repository update...]"
if [ -s payloads/<default_github_private_key_filename> ]
then
    echo "[Starting to process GitHub repository update...]"
    echo "[Adding GitHub as known host to root...]"
    # Add github.com to the known_hosts file
    ssh-keyscan -H github.com >> /root/.ssh/known_hosts
    # Copy the GitHub SSH keys to /root/.ssh directory
    echo "[Moving GitHub SSH keys to root...]"
    cp /root/payloads/<default_github_private_key_filename> /root/.ssh
    cp /root/payloads/<default_github_private_key_filename>.pub /root/.ssh
    # Modify permissions
    chmod 0400 /root/.ssh/<default_github_private_key_filename>
    chmod 0400 /root/.ssh/<default_github_private_key_filename>.pub
    # Copy the <default_github_private_key_filename> to ssh-agent
    echo "[Adding GitHub SSH keys to root ssh agent...]"
    eval `ssh-agent -s`
    ssh-add /root/.ssh/<default_github_private_key_filename>
    # For each repository listed in githubuser file
    while read -r -a githubuser
    do
      # Eliminate comments
      if [[ ${githubuser[0]:0:1} != "#" && ! -z "${githubuser[0]}" ]]; then
        #
        # Push the live site to the GitHub repository 'live' branch
        #
        cd /var/www/html/${githubuser[0]}
        # Create a branch for current state
        git branch $(date '+%Y-%m-%d')
        git checkout $(date '+%Y-%m-%d')
        # Push the current site to the live branch
        git fetch . main:live
        # Switch to the live branch
        git checkout live
        # Add the changes to the live branch
        git add -A
        echo "[Commiting changes to GitHub repository...]"
        git commit -m "Auto commit from server"
        echo "[Pushing commits to GitHub repository...]"
        git push origin live
        # Switch back to the main branch
        git checkout main
        # Set permissions files for host domain
        echo "[Re-writing ownership...]"
        chown -R apache:apache /var/www/html/${githubuser[0]}
        echo "[Finished re-writing ownership...]"
      fi
    done < payloads/github_userdata
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
