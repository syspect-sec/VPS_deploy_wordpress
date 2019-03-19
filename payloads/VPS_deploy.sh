#!/bin/bash
#
#
# VPS_deploy.sh
# Main Server Deployment Script
#
# GitHub: https://github.com/rippledj/VPS_deploy_wordpress
# Author: Joseph Lee
# Email: joseph@ripplesoftware.ca
#
#
# Set the timezone and configure time
#
# Install the NTP date
yum install -y ntp
yum install -y ntpdate
# Check that ntpd is running
chkconfig ntpd on
# Set ntpd as a service
systemctl enable ntpd
# Sync the time to pool.ntp.org
ntpdate pool.ntp.org
# Start the ntpd daemon
systemctl start ntpd
# Set the hardware clock to server clock
hwclock -w
# Set the server to use NTP time
timedatectl set-ntp yes
# Set the local time zone
timedatectl set-local-rtc 0
#
# Enable persistant log journaling
#
mkdir /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald
#
# Creat Swap space and enable
#
fallocate -l 1G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
swapon --show
free -h
# Install Firewalld
#
echo "[Installing firewalld...]"
yum install -y firewalld
systemctl start firewalld
systemctl enable firewalld
systemctl enable firewalld.service
echo "[firwalld installed, enabled, and added to systemctl services...]"
#
# Install Fail2ban
#
echo "[Installing fail2ban...]"
yum install -y fail2ban
/bin/cp payloads/jail.local /etc/fail2ban/jail.local
systemctl restart fail2ban
systemctl enable fail2ban
fail2ban-client status
echo "[fail2ban installed, enabled, and added to systemctl services...]"
#
# User Account Creation
#
# Use decrypted user_data file to create required users
echo "[Performing user account modifications to the server...]"
while read -r -a user
do
  # Eliminate all comment lines
  if [[ ${user[0]:0:1} != "#" && ! -z "${user[0]}" ]]; then
    if [ ${user[0]} = "root" ]; then
      echo "${user[0]}:${user[1]}" | chpasswd
      echo "[Root password changed...]"
    else
      useradd ${user[0]}
      echo "${user[0]}:${user[1]}" | chpasswd
      echo "[New non-root user ${user[0]} added...]"
      # Add user to sudoer group.
      usermod -aG wheel ${user[0]}
      echo "[New non-root user added to sudoers group...]"
    fi
  fi
done < payloads/userdata
echo "[Finished user account modifications to the server...]"
#
# Setup SSH for User Accounts
#
# Use payloads/userdata to create required users ssh dir
# TODO: add option to change the SSH key in the payload
echo "[Moving SSH keys to new users...]"
while read -r -a user
do
  if [ ${user[0]} != "root" ]; then
    # Setup SSH for user access
    mkdir /home/${user[0]}/.ssh
    chown ${user[0]}:${user[0]} /home/${user[0]}/.ssh
    chmod 500 /home/${user[0]}/.ssh
    # TODO: Check if moving authorized_keys is required here
    mv /home/centos/.ssh/authorized_keys /home/${user[0]}/.ssh/authorized_keys
    chown ${user[0]}:${user[0]} /home/${user[0]}/.ssh/authorized_keys
    chmod 0400 /home/${user[0]}/.ssh/authorized_keys
    # Remove the .ssh folder for centos user
    rm -rf /centos/.ssh
    echo "[SSH keys moved to new non-root user ~/.ssh...]"
    #echo "[SSH access now only available to non-root user ${user[0]}...]"
  fi
done < payloads/userdata
# TODO: Check that Grub is install on server and config if needed
#
# Update CentOS and Repositories
#
#TODO: update and upgrade was failing on the DO server.
#echo "[Updating and upgrading OS...]"
#yum -y update && upgrade
#echo "[OS updated and upgraded...]"
# Install epel repository
echo "[Adding epel repository...]"
yum install -y epel-release
echo "[Added epel repository...]"
#
# Install LAMP Web-stack
#
# Install Apache
echo "[Installing Apache...]"
yum install -y httpd
echo "[Apache installed...]"
# Install PHP
# Step 1: Install Webstatic repositories
echo "[Installing PHP...]"
#
# Install PHP 7.1 and necessary extensions
#
rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm
yum install -y mod_php71w php71w-cli php71w-common php71w-gd php71w-mbstring php71w-mcrypt php71w-mysqlnd php71w-xml
#
# Install PHP 5.5
#
#rpm -Uvh http://vault.centos.org/7.0.1406/extras/x86_64/Packages/epel-release-7-5.noarch.rpm
#yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
#yum --enablerepo=remi,remi-php55 -y install php php-common
#yum --enablerepo=remi,remi-php55 -y install php-cli php-pdo php-mysql php-mysqlnd php-gd php-mcrypt php-xml php-simplexml php-zip
echo "[PHP installed...]"
# Install MySQL / MariaDB
# NOTE: Check that differences between MySQL and MariaDB
# Method 1: MySQL / MariaDB from default repository
echo "[Installing MySQL/MariaDB...]"
yum install -y mariadb-server
# Replace MySQL/MariaDB my.conf file with payload/my.cnf
echo "[Replacing MySQL/MariaDB configuration file...]"
/bin/cp payloads/my.cnf /etc/my.cnf
# Start MySQL/MariaDB and add to boot services
echo "[Starting MySQL/MariaDB...]"
systemctl start mariadb
systemctl enable mariadb
systemctl status mariadb
echo "[MySQL/MariaDB installed, started and added to system services...]"
# Method 2: Installed from newest packages available online
#wget -N https://dev.mysql.com/get/mysql-community-server-8.0.12-1.el7.x86_64.rpm
#rpm -ivh mysql-community-server-8.0.12-1.el7.x86_64.rpm
#yum update
#yum localinstall -y mysql-community-release-el7-5.noarch.rpm
#systemctl start mysqld
#systemctl enable mysqld
#echo "[MySQL installed from rpm and started...]"
# Perform tasks performed by mysql_secure_installation
# If there is anything in the mysql_userdata file then add mysql root password and backup user
#
# Modify Configuration of LAMP Web-stack
#
if [ -s payloads/mysql_userdata ]
then
  echo "[Starting to process MySQL/MariaDB user config...]"
  while read -r -a mysqlpass
  do
    if [ ${mysqlpass[0]} = "root" ]; then
      # Make sure that nobody can access the server without a password
      mysql -e "UPDATE mysql.user SET Password = PASSWORD('${mysqlpass[1]}') WHERE User = 'root';"
      echo mysql -e "UPDATE mysql.user SET Password = PASSWORD('redacted') WHERE User = 'root';"
      echo "[MySQL root password changed...]"
    elif [ ${mysqlpass[0]} = "backup" ]; then
      mysql -e "CREATE USER 'backup'@'localhost' IDENTIFIED BY '${mysqlpass[1]}';"
      echo mysql -e "CREATE USER 'backup'@'localhost' IDENTIFIED BY 'redacted';"
      mysql -e "GRANT SELECT, SHOW VIEW, RELOAD, REPLICATION CLIENT, EVENT, TRIGGER ON *.* TO 'backup'@'localhost';"
      echo mysql -e "GRANT SELECT, LOCK TABLES, SHOW VIEW, RELOAD, REPLICATION CLIENT, EVENT, TRIGGER ON *.* TO 'backup'@'localhost';"
      echo "[MySQL backup user created...]"
    fi
  done < payloads/mysql_userdata
fi
# Perform the tasks that would  normally be done by MySQL secure installation
echo "[Starting to process MySQL secure installation...]"
# Remove remote login for root
mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
echo mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
echo "[MySQL removed remote login for root...]"
# Remove the anonymous users
mysql -e "DROP USER ''@'localhost';"
echo mysql -e "DROP USER ''@'localhost';"
echo "[MySQL removed anonymous users...]"
# Because our hostname varies we'll use some Bash magic here.
mysql -e "DROP USER ''@'$(hostname)';"
echo mysql -e "DROP USER ''@'$(hostname)';"
echo "[MySQL removed hostname user...]"
# Remove off the demo database
mysql -e "DROP DATABASE test;"
echo mysql -e "DROP DATABASE test;"
echo "[MySQL removed demo database...]"
# Make our changes take effect
mysql -e "FLUSH PRIVILEGES"
echo mysql -e "FLUSH PRIVILEGES"
echo "[MySQL flushed privileges...]"
# Set SELinux Policy to allow mysql connections
echo "[Allowing SELinux policy for MySQL connection...]"
setsebool -P selinuxuser_mysql_connect_enabled 1
setsebool -P httpd_can_network_connect_db 1
echo "[SELinux policy has allowed MySQL connection]"
# Finally open firewall to web-access
echo "[Adding web-ports to firewalld...]"
firewall-cmd --add-service=http
firewall-cmd --add-service=https
echo "[Web-ports added to allowed firewalld...]"
# Mail server to the firewall allowed
# By service
echo "[Adding mailserver to firewalld...]"
firewall-cmd --add-service=smtp
#firewall-cmd --permanent --add-port=587/tcp
firewall-cmd --permanent --add-port=465/tcp
echo "[Mail-ports added to firewall...]"
echo "[Allowing SELinux policy for mailserver...]"
setsebool -P httpd_can_sendmail 1
echo "[SELinux policy has allowed SMTP Mail...]"
# Set all firewall permanant and reload
echo "[Reloading firewall with changes...]"
firewall-cmd --runtime-to-permanent
firewall-cmd --reload
echo "[Firewall reloaded with changes...]"
#
# GitHub Repository Clone and Web-App Configuration
#
# Connect to GitHub and install the website
# NOTE:Your github ssh pub key needs to have been added to GitHub already
if [ -s payloads/id_rsa_github ]
then
    echo "[Starting to process Git installation...]"
    # Install Git
    yum -y install git
    echo "[Git installed...]"
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
    # Copy the id_rsa_github and id_rsa_github.pub to /root/.ssh directory
    echo "[Adding GitHub SSH keys to root ssh agent...]"
    eval `ssh-agent -s`
    ssh-add /root/.ssh/id_rsa_github
    # For each repository listed in githubuser file
    while read -r -a githubuser
    do
      # Eliminate comments
      if [[ ${githubuser[0]:0:1} != "#" && ! -z "${githubuser[0]}" ]]; then
        # Clone the repo for the site to be installed
        echo "[Cloning repository into web-root directory...]"
        git clone git@github.com:${githubuser[1]}/${githubuser[0]}.git /var/www/html/${githubuser[0]}
        # Remove the ssh-agent deamon
        eval `ssh-agent -k`
        echo "[ssh-agent process killed...]"
        echo "[GitHub repo successfully cloned...]"
        # Set permissions files for host domain
        echo "[Re-writing ownership...]"
        chown -R apache:apache /var/www/html/${githubuser[0]}
        echo "[Finished re-writing ownership...]"
        # Load a list of directories that will require special owners
        echo "[Processing script specified file ownership...]"
        while read -r -a own
        do
          # Eliminate all comment lines
          if [[ ${own[0]:0:1} != "#" && ! -z "${own[0]}" ]]; then
            # If file is specified, file all files and chmod
            echo "chown ${own[0]}"
            chown ${own[0]}
          fi
        done < payloads/site_ownership
        echo "[Finished processing script specified file ownership...]"
        # Load a list of directories that will require special permissions
        echo "[Processing script specified permisssions...]"
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
                find ${dirperm[2]} -type d -exec chcon -t httpd_sys_content_t -R ${dirperm[2]} -- {} +
              else
                echo "SE Directory Read Mode: ${dirperm[1]}"
                chcon -t httpd_sys_content_t ${dirperm[1]}
              fi
            fi
            # If SELinux dir specified open directory for SELinux read/write
            if [ ${dirperm[0]} = "<se-dir-read-write>" ]; then
              if [ ${dirperm[1]} = "-R" ]; then
                echo "SE Directory Read/Write Recursive Mode: ${dirperm[2]}"
                find ${dirperm[2]} -type d -exec chcon -t httpd_sys_rw_content_t -R -- {} +
              else
                echo "SE Directory Read/Write Mode: ${dirperm[1]}"
                chcon -t httpd_sys_rw_content_t ${dirperm[1]}
              fi
            fi
          fi
        done < payloads/site_permissions
        echo "[Finished processing script specified permisssions...]"
        # Run any additional scripts that are included in the github package
        echo "[Processing other speficied scripts included in GitHub repository...]"
        if [ -s payloads/additional_scripts ]
        then
          while read -r -a script
          do
            # Eliminate all comment lines
            if [[ ${script[0]:0:1} != "#" && ! -z "${script[0]}" ]]; then
              echo "/var/www/html/${githubuser[0]}/${script[0]}"
              /var/www/html/${githubuser[0]}/${script[0]}
            fi
          done < payloads/additional_scripts
          echo "[Finished processing additional scripts...]"
        fi
        # Install any MySQL scripts that are included in the GitHub package
        echo "[Processing specified MySQL scripts included in GitHub repository...]"
        if [ -s payloads/mysql_userdata ]
        then
          while read -r -a mysqlpass
          do
            # Eliminate all comment lines
            if [[ ${mysqlpass[0]:0:1} != "#" && ! -z "${mysqlpass[0]}" ]]; then
              if [ ${mysqlpass[0]} = "root" ]; then
                # Install each script in the mysql_scripts file
                if [ -s payloads/mysql_scripts ]
                then
                  while read -r -a mysqlscript
                  do
                    if [[ ${mysqlscript[0]:0:1} != "#" && ! -z "${mysqlscript[0]}" ]]; then
                      echo "[Installing MySQL script /var/www/html/${githubuser[0]}/${mysqlscript[0]}...]"
                      mysql -f -u root -p${mysqlpass[1]} mysql < /var/www/html/${githubuser[0]}/${mysqlscript[0]}
                      echo "[Finished installing MySQL script /var/www/html/${githubuser[0]}/${mysqlscript[0]}...]"
                    fi
                  done < payloads/mysql_scripts
                fi
              fi
            fi
          done < payloads/mysql_userdata
        fi
        echo "[Finished processing MySQL scripts...]"
        # Create  V-host files for host domain
        echo "[Adding a V-host to Apache...]"
        mkdir /etc/httpd/sites-available
        mkdir /etc/httpd/sites-enabled
        echo "[File structure added for Apache V-host...]"
        /bin/cp payloads/V_host.conf /etc/httpd/sites-available/${githubuser[0]}.conf
        echo "[V-host file moved to sites-available...]"
        ln -s /etc/httpd/sites-available/${githubuser[0]}.conf /etc/httpd/sites-enabled/${githubuser[0]}.conf
        echo "[V-host enabled...]"
        echo "[V-host added to Apache...]"
      fi
    done < payloads/github_userdata
    # Move modified httpd.conf
    echo "[Replacing Apache httpd.conf config file...]"
    /bin/cp payloads/httpd.conf /etc/httpd/conf/httpd.conf
    # TODO: secure httpd.conf file with strict permissions
    chmod 0440 /etc/httpd/conf/httpd.conf
    echo "[Apache config file replaced...]"
    # Move modified php.ini
    echo "[Replacing PHP config php.ini file...]"
    /bin/cp payloads/php.ini /etc/php.ini
    # TODO: secure php.ini file with strict permissions
    chmod 0440 /etc/php.ini
    echo "[PHP config file replaced...]"
fi
#
# Fireup the Web-Server
#
# Start Apache
echo "[Starting Apache...]"
service httpd start
# Set Apache to start on server boot
echo "[Addding Apache to system services...]"
systemctl enable httpd.service
echo "[Apache started and added to system services...]"
#
# Install Additional Security Scripts
#
# Install rkhunter
echo "[Installing rkhunter...]"
yum install -y rkhunter
# Update rkhunter
rkhunter --update
echo "[rkhunter added and updated...]"
# Run rkhunter to get initial image of system settings
echo "[Creating rkhuner stored file properties (rkhunter.dat)...]"
rkhunter --propupd
# TODO: rkhunter -c -sk is not completing scan... thinks
#echo "[rkhunter stored files properties file created...]"
#rkhunter -c --sk
#echo "[rkhunter has completed first scan of system...]"
# Continue to install non critical softare
echo "[Installing logrotate...]"
yum install -y logrotate
echo "[logrotate Installed...]"
echo "[Installing nano...]"
yum install -y nano
echo "[nano Installed...]"
echo "[Installing required python packages...]"
yum install -y python-dateutil
yum install -y MySQL-python
yum install -y mysql-devel
pip install psycopg2
pip install psycopg2-binary
echo "[Installing required python packages...]"
#
# Install Crontab Schedule Jobs
#
# Install crons from file first
echo "[Intializing crontab and adding crontabs from payload...]"
crontab payloads/crons
# Install cron for rkhunter
echo "[Adding rkhunter to crontabs...]"
crontab -l | { cat; echo "0 0 * * 0 rkhunter -c --sk"; } | crontab -
crontab -l | { cat; echo "0 0 * * 0 rpm -V initscripts >> /var/log/initscripts.log"; } | crontab -
# Install database backup crons
echo "[Adding MySQL backup to crontabs...]"
if [ -s payloads/mysql_userdata ]; then
  while read -r -a mysqlpass
  do
    if [ ${mysqlpass[0]} = "backup" ]; then
      mkdir -p /var/www/html/<github_reponame>/extra_files/database/backups
      chmod o+w /var/www/html/<github_reponame>/extra_files/database/backups
      crontab -l | { cat; echo "0 0 * * 1 mysqldump --single-transaction -u backup -p${mysqlpass[1]} --all-databases | gzip > /var/www/html/<github_reponame>/backups/db_backup_\$(date +\%m_\%d_\%Y).sql.gz"; } | crontab -
    fi
  done < payloads/mysql_userdata
fi
# Install a cron to check that MySQL is running at all times
echo "[Adding MySQL status checking and restart to crontabs...]"
crontab -l | { cat; echo "* * * * * root service mariadb status || service mariadb start"; } | crontab -
# Install GitHub push and scp database backup to remote server
echo "[Adding GitHub and remote database backup to crontabs...]"
crontab -l | { cat; echo "0 5 * * 1 python ./root/VPS_deploy.py -backup -p $1"; } | crontab -
echo "[Finished adding crontabs to schedule...]"
#
# SSHD Conifiguration
#
# TODO: figure out the best config for sshd_config that works
# Move the sshd config file onto the server
echo "[Moving new sshd_config to server...]"
/bin/cp payloads/sshd_config /etc/ssh/sshd_config
systemctl restart sshd
echo "[New sshd_config moved to server...]"
echo "[Removing root SSH directory...]"
rm -rf /root/.ssh
echo "[Root SSH directory removed...]"
#
# Configure SSL/TLS on the Domain
#
# Install required SSL packages
echo "[Installing required packages for SSL...]"
yum install -y mod_ssl python-certbot-apache
# Restart Apache
echo "[Restarting Apache...]"
systemctl restart httpd
# Show status of Apache
systemctl status httpd
# Move the payload and main script to the server, and run remotely
# TODO: use tool to autocomplete the requried input such as email address, etc. "2" into the certbot command
echo "[Registering a SSL certificate with Let's Encrypt...]"
while read -r -a sshdata
do
  # Eliminate all comment lines
  if [[ ${sshdata[0]:0:1} != "#" && ! -z "${sshdata[0]}" ]]; then
    if [ ${sshdata[0]} = "DomainName" ]; then
      certbot --non-interactive --agree-tos --redirect --hsts --uir -m <your@emailaddress.com> --apache -d ${sshdata[1]} -d www.${sshdata[1]}
    fi
  fi
done < serverdata
echo "[SSL certificate registered...]"
/bin/cp payloads/ssl.conf /etc/httpd/conf.d/ssl.conf
echo "[Moved SSL configuration file to Apache...]"
echo "[Adding a crontab schedule to renew SSL certificates...]"
crontab -l | { cat; echo "30 2 * * * /usr/bin/certbot renew >> /var/log/le-renew.log"; } | crontab -
echo "[Scheduled a autorenew of SSL certificates...]"
# Restart Apache
echo "[Restarting Apache...]"
systemctl restart httpd
# Show status of Apache
systemctl status httpd
echo "[Apache restarted...]"
# TODO: adjust the ~/.ssh/config file to specify the ssd_config port on client
# TODO: Check if the sshd_config file port, if it's not 22, then
# add to firewall and SELinux
# Allow the port that ssh will run on
# For Port 22
#firewall-cmd --permanent --add-service=ssh
#firewall-cmd --permanent --add-port=22/tcp
# For another port
#echo firewall-cmd --permanent --remove-service=ssh
#echo firewall-cmd --permanent --add-port=#PORTNUMBER/tcp
# SELinux needs to allow the new SSH port
#semanage port -a -t ssh_port_t -p tcp #PORTNUMBER
#echo "[SSH port added to firewall...]"
#TODO: install SeLinux notifications
#TOD0: configure SELinux to disable printenv or other environment variable disclosing commands
#
# Apache Config Locker
#
# Encrypt the httpd.conf file
echo "[Closing Apache config using Apache config locker...]"
python payloads/apache_config_locker.py -close -p $1
echo "[Apache config closed...]"
#
# VPS_deploy Cleanup
#
# If the purge flag has been set
if [ $2 = 1 ]; then
  echo "[Removing VPS_deploy payload...]"
  echo "[Moving scripts that are not part of the payload...]"
  mv payloads/VPS_close.sh /root/
  mv payloads/VPS_open.sh /root/
  mv payloads/VPS_update_git.sh /root/
  mv payloads/VPS_apachectl.sh /root/
  mv payloads/apache_config_locker.py /root/
  echo "[Scripts moved...]"
  rm -rf payloads
  echo "[VPS_deploy payload has been removed...]"
fi
# Clear the command line history
echo "[Removing command line history...]"
history -c
rm -rf /root/.bash_history
echo "[Command line history removed...]"
# Power-off for image of server or reboot system
while read -r -a finish
do
  # Eliminate all comment lines
  if [[ ${finish[0]:0:1} != "#" && ! -z "${finish[0]}" ]]; then
    if [ ${finish[0]} = "poweroff" ] && [ ${finish[1]} = "1" ]; then
      echo "[Powering off VPS server... image me!...]"
      poweroff
    fi
    if [ ${finish[0]} = "reboot" ] && [ ${finish[1]} = "1" ]; then
      echo "[Rebooting VPS server... see you soon!...]"
      reboot
    fi
    if [ ${finish[0]} = "close" ] && [ ${finish[1]} = "1" ]; then
      # Close the payload
      echo "[Closing the payload...]"
      python ./VPS_deploy.py -load -p $5
      echo "[Payload closed...]"
    fi
  fi
done < payloads/finish
