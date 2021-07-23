#!/bin/bash
#
#
# VPS_update_git.sh
# Update Live Site from GitHub
#
# GitHub: https://github.com/rippledj/VPS_deploy_wordpress
# Author: Joseph Lee
# Email: joseph@ripplesoftware.ca
#
echo "[Updating GitHub repository...]"
if [ -s payloads/<default_github_private_key_filename> ]
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
    # Copy the GitHub SSH keys to /root/.ssh directory
    echo "[Moving GitHub SSH keys to root...]"
    /bin/cp payloads/<default_github_private_key_filename> /root/.ssh
    /bin/cp payloads/<default_github_private_key_filename>.pub /root/.ssh
    # Modify permissions
    chmod 0400 /root/.ssh/<default_github_private_key_filename>
    chmod 0400 /root/.ssh/<default_github_private_key_filename>.pub
    # Copy the GitHub SSH keys to /root/.ssh directory
    echo "[Adding GitHub SSH keys to root ssh agent...]"
    eval `ssh-agent -s`
    ssh-add /root/.ssh/<default_github_private_key_filename>
    # For each repository listed in githubuser file
    while read -r -a githubuser
    do
      # Eliminate comments
      if [[ ${githubuser[0]:0:1} != "#" && ! -z "${githubuser[0]}" ]]; then
        echo "[Fetching GitHub repository...]"
        cd /var/www/html/${githubuser[0]}
        #
        # Pull the changes from the GitHub repository 'master' branch
        #
        git fetch --all
        echo "[Resetting GitHub repository...]"
        git reset --hard origin/master
        echo "[Finished Updating GitHub repository...]"
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
echo "[VPS_deploy has updated your GitHub repository...]"
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
