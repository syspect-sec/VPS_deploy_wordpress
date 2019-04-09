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
/bin/cp payloads/ssh_identity_file /root/.ssh/
mv /root/.ssh/ssh_identity_file /root/.ssh/config
chmod 0400 /root/.ssh/config
#
# Push the newly created database backup to the backup server
#
echo "[Starting to secure copy datbase backup to the server...]"
if [ -s payloads/id_rsa_backup ]
then
    echo "[Adding backup server IP as known host to root...]"
    # Add github.com to the known_hosts file
    ssh-keyscan -H <default_remote_backup_IP> >> /root/.ssh/known_hosts
    # Copy the id_rsa_github and id_rsa_github.pub to /root/.ssh directory
    echo "[Moving backup server SSH keys to root...]"
    /bin/cp payloads/id_rsa_backup /root/.ssh
    /bin/cp payloads/id_rsa_backup.pub /root/.ssh
    # Modify permissions
    chmod 0400 /root/.ssh/id_rsa_backup
    chmod 0400 /root/.ssh/id_rsa_backup.pub
    # Copy the id_rsa_github and id_rsa_github.pub to /root/.ssh directory
    echo "[Adding backup server SSH keys to root ssh agent...]"
    eval `ssh-agent -s`
    ssh-add /root/.ssh/id_rsa_backup
    # Get the GitHub reponame to put define the server
    while read -r -a githubuser
    do
      # Eliminate comments
      if [[ ${githubuser[0]:0:1} != "#" && ! -z "${githubuser[0]}" ]]; then
        # Create a full backup of the database
        echo "[Create a MySQL full database backup...]"
        if [ -s payloads/mysql_userdata ]; then
          while read -r -a mysqlpass
          do
            if [ ${mysqlpass[0]} = "backup" ]; then
              mysqldump --single-transaction -u backup -p${mysqlpass[1]} --all-databases | gzip > /var/www/backups/${githubuser[1]}/db_backup_\$(date +\%m_\%d_\%Y).sql.gz
            fi
          done < payloads/mysql_userdata
        fi
        # Clone the repo for the site to be installed
        echo "[Secure copy the database backup to the repository folder on the backup server...]"
        while read -r -a remoteserver
        do
          scp /var/www/backups/${githubuser[1]}/db_backup_\$(date +\%m_\%d_\%Y).sql.gz ${remoteserver[0]}@${remoteserver[1]}:~${githubuser[1]}
        done < payloads/remote_serverdata
      fi
    done < payloads/github_userdata
fi
echo "[VPS_deploy has finished sending databse backup to remote server...]"
#
# Perform GitHub backup actions
#
echo "[Starting to process GitHub repository update...]"
if [ -s payloads/id_rsa_github ]
then
    echo "[Starting to process GitHub repository update...]"
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
        git push origin master
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
# Clean up
#
# Clear the command line history
echo "[Removing command line history...]"
history -c
> /root/.bash_history
echo "[Command line history removed...]"
echo "[Removing SSH directory...]"
rm -rf /root/.ssh
echo "[SSH directory removed...]"
# Send a success exit code
exit 0
