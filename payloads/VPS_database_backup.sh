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
# Backup the database remotely
#
echo "[Starting to secure copy datbase backup to the server...]"
if [ -s payloads/id_rsa_backup ]
then
    echo "[Adding backup server IP as known host to root...]"
    # Add github.com to the known_hosts file
    ssh-keyscan -H <default_remote_backup_IP> >> /root/.ssh/known_hosts
    # Copy the SSH keys used for backing up files to /root/.ssh directory
    echo "[Moving backup server SSH keys to root...]"
    /bin/cp payloads/id_rsa_backup /root/.ssh
    /bin/cp payloads/id_rsa_backup.pub /root/.ssh
    # Modify permissions
    chmod 0400 /root/.ssh/id_rsa_backup
    chmod 0400 /root/.ssh/id_rsa_backup.pub
    # Copy the GitHub access SSH keys to /root/.ssh directory
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
        setdate=`date +%s`
        if [ -s payloads/mysql_userdata ]; then
          while read -r -a mysqlpass
          do
            if [ ${mysqlpass[0]} = "backup" ]; then
              mysqldump --single-transaction -u backup -p${mysqlpass[1]} --all-databases | gzip > /var/www/backups/${githubuser[1]}/db_backup_\${setdate}.sql.gz
            fi
          done < payloads/mysql_userdata
        fi
        # Clone the repo for the site to be installed
        echo "[Secure copy the database backup to the repository folder on the backup server...]"
        while read -r -a remoteserver
        do
          scp /var/www/backups/${githubuser[1]}/db_backup_\${setdate}.sql.gz ${remoteserver[0]}@${remoteserver[1]}:~${githubuser[1]}
        done < payloads/remote_serverdata
      fi
    done < payloads/github_userdata
fi
echo "[VPS_deploy has finished sending databse backup to remote server...]"
#
# Clean up
#
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
