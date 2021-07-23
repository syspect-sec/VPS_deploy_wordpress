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
# Install epel repository
#
echo "[Adding epel repository...]"
yum install -y epel-release
echo "[Added epel repository...]"
#
# Set the timezone and configure time
#
# Install the NTP date
echo "[Configuring server time...]"
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
echo "[Server time configured...]"
#
# Enable persistant log journaling
#
mkdir /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald
#
# Creat Swap space and enable
#
echo "[Creating swap space...]"
sudo dd if=/dev/zero of=/swapfile count=2096 bs=1MiB
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
swapon --show
swapon --summary
free -h
echo "[Swap space created...]"
#
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
/bin/cp payloads/ban.conf /etc/fail2ban/ban.conf
/bin/cp payloads/multiban.conf /etc/fail2ban/filter.d/multiban.conf
/bin/cp payloads/http-get-dos.conf /etc/fail2ban/filter.d/http-get-dos.conf
/bin/cp payloads/http-post-dos.conf /etc/fail2ban/filter.d/http-post-dos.conf
systemctl restart fail2ban
systemctl enable fail2ban
fail2ban-client status
echo "[fail2ban installed, enabled, and added to systemctl services...]"
#
# Install Clamscan
#
echo "[Installing ClamAV...]"
#yum install -y clamav clamav-update clamav-scanner-systemd clamav-server-systemd
yum -y install clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd
sed -i -e "s/^Example/#Example/" /etc/freshclam.conf
sed -i -e "s/^Example/#Example/" /etc/clamd.d/scan.conf
# Configure SELinux to allow virus scanning
setsebool -P antivirus_can_scan_system 1
setsebool -P clamd_use_jit 1
echo "[ClamAV installed enabled and added to systemctl services...]"
echo "[Updating ClamAV signatures...]"
freshclam
clamd -V
echo "[ClamAV Installed...]"
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
#
# Install LAMP Web-stack
#
# Install Apache
echo "[Installing Apache...]"
yum install -y httpd
echo "[Apache installed...]"
/bin/cp /etc/mime.types /etc/httpd/conf/mime.types
echo "[Moved mime.types file to /etc/httpd/conf directory...]"
#
# Install PHP 7.1 and necessary extensions
#
echo "[Installing PHP...]"
if [ -s payloads/php_version ]
then
  while read -r -a phpversion
  do
    if [ ${phpversion} = "7.4" ]; then
      yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
      yum install -y yum-utils
      yum-config-manager --enable remi-php74
      yum install php php-pdo php-fpm php-gd php-mbstring php-mysql php-curl php-mcrypt php-json -y
    elif [ ${phpversion} = "7.3" ]; then
      yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
      yum install -y yum-utils
      yum-config-manager --enable remi-php73
      yum install php php-pdo php-fpm php-gd php-mbstring php-mysql php-curl php-mcrypt php-json -y
    elif [ ${phpversion} = "7.2" ]; then
      yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
      yum install -y yum-utils
      yum-config-manager --enable remi-php72
      yum install php php-pdo php-fpm php-gd php-mbstring php-mysql php-curl php-mcrypt php-json -y
    elif [ ${phpversion} = "7.1" ]; then
      rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm
      yum install -y mod_php71w php71w-cli php71w-common php71w-gd php71w-mbstring php71w-mcrypt php71w-mysqlnd php71w-xml
    elif [ ${phpversion} = "5.6" ]; then
      rpm -Uvh http://vault.centos.org/7.0.1406/extras/x86_64/Packages/epel-release-7-5.noarch.rpm
      yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
      yum --enablerepo=remi,remi-php56 -y install php php-common
      yum --enablerepo=remi,remi-php56 -y install php-cli php-pdo php-mysql php-mysqlnd php-gd php-mcrypt php-xml php-simplexml php-zip
    elif [ ${phpversion} = "5.5" ]; then
      rpm -Uvh http://vault.centos.org/7.0.1406/extras/x86_64/Packages/epel-release-7-5.noarch.rpm
      yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
      yum --enablerepo=remi,remi-php55 -y install php php-common
      yum --enablerepo=remi,remi-php55 -y install php-cli php-pdo php-mysql php-mysqlnd php-gd php-mcrypt php-xml php-simplexml php-zip
    fi
  done < payloads/php_version
fi
echo "[PHP installed...]"
#
# Install Database Application
#
echo "[Installing Database Application...]"
if [ -s payloads/db_version ]
then
  while read -r -a dbversion
  do
    if [ ${dbversion} = "mariadb" ]; then
      # Install MariaDB from default repository
      echo "[Installing MariaDB...]"
      yum install -y mariadb-server
      # Replace MySQL/MariaDB my.conf file with payload/my.cnf
      echo "[Replacing MariaDB configuration file...]"
      /bin/cp payloads/my.cnf /etc/my.cnf
      # Start MySQL/MariaDB and add to boot services
      echo "[Starting MariaDB...]"
      systemctl start mariadb
      systemctl enable mariadb
      systemctl status mariadb
      echo "[MariaDB installed, started and added to system services...]"
    elif [ ${dbversion} = "mysql" ]; then
      # Install MySQL from default repository
      echo "[Installing MySQL...]"
      wget -N https://dev.mysql.com/get/mysql-community-server-8.0.12-1.el7.x86_64.rpm
      rpm -ivh mysql-community-server-8.0.12-1.el7.x86_64.rpm
      yum update
      yum localinstall -y mysql-community-release-el7-5.noarch.rpm
      systemctl start mysqld
      systemctl enable mysqld
      echo "[MySQL installed from rpm and started...]"
      # Perform tasks performed by mysql_secure_installation
      # If there is anything in the mysql_userdata file then add mysql root password and backup user
    elif [ ${dbversion} = "postgres" ]; then
      yum install postgresql-server postgresql-contrib
      sudo systemctl start postgresql
      sudo systemctl enable postgresql

    fi
  done < payloads/db_version
fi
echo "[Database Application installed...]"
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
    else
      mysql -e "CREATE USER '${mysqlpass[0]}'@'localhost' IDENTIFIED BY '${mysqlpass[1]}';"
      echo mysql -e "CREATE USER '${mysqlpass[0]}'@'localhost' IDENTIFIED BY 'redacted';"
      echo mysql -e "GRANT ALL ON <default_github_reponame>.* TO '${mysqlpass[0]}'@'localhost';"
      echo "[MySQL site user created...]"
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
#
# Set SELinux Policy to allow mysql connections
#
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
if [ -s payloads/<default_github_private_key_filename> ]
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
    # Copy the GitHub SSH Keys to /root/.ssh directory
    echo "[Moving GitHub SSH keys to root...]"
    /bin/cp payloads/<default_github_private_key_filename> /root/.ssh
    /bin/cp payloads/<default_github_private_key_filename>.pub /root/.ssh
    # Modify permissions
    chmod 0400 /root/.ssh/<default_github_private_key_filename>
    chmod 0400 /root/.ssh/<default_github_private_key_filename>.pub
    # Copy the <default_github_private_key_filename> and <default_github_private_key_filename>.pub to /root/.ssh directory
    echo "[Adding GitHub SSH keys to root ssh agent...]"
    eval `ssh-agent -s`
    ssh-add /root/.ssh/<default_github_private_key_filename>
    # For each repository listed in githubuser file
    while read -r -a githubuser
    do
      # Eliminate comments
      if [[ ${githubuser[0]:0:1} != "#" && ! -z "${githubuser[0]}" ]]; then
        # Clone the repo for the site to be installed
        echo "[Cloning repository into web-root directory...]"
        git clone git@github.com:${githubuser[1]}/${githubuser[0]}.git /var/www/html/${githubuser[0]}
        # Create a `live` branch in the repo
        (cd /var/www/html/${githubuser[0]} && git branch live)
        # Remove the ssh-agent deamon
        eval `ssh-agent -k`
        echo "[ssh-agent process killed...]"
        echo "[GitHub repo successfully cloned...]"
        # Check for and move WordPress uploads directory
        echo "[Checking for WordPress uploads directory to move...]"
        if [ -e uploads.tar.gz ]
        then
          echo "[Moving uploads directory to WordPress installation...]"
          rm -rf /var/www/html/${githubuser[0]}/wp-content/uploads
          mv uploads.tar.gz /var/www/html/${githubuser[0]}/wp-content
          echo "[Upacking WordPress uploads directory...]"
          gunzip /var/www/html/${githubuser[0]}/wp-content/uploads.tar.gz
          echo "[WordPress uploads directory moved and unpacked...]"
        else
          echo "[No WordPress uploads directory found...]"
        fi
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
systemctl enable httpd
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
echo "[rkhunter stored files properties file created...]"
# TODO: rkhunter -c -sk is not completing scan... thinks
#rkhunter -c --sk
#echo "[rkhunter has completed first scan of system...]"
# Continue to install non critical softare
echo "[Installing logrotate...]"
yum install -y logrotate
echo "[logrotate Installed...]"
echo "[Installing nano...]"
yum install -y nano
echo "[nano Installed...]"
echo "[Installing additional packages...]"
yum install -y yum-plugin-protectbase.noarch
echo "[Installing required python packages...]"
yum install -y python-dateutil
yum install -y MySQL-python
yum install -y mysql-devel
echo "[Finished installing required python packages...]"
#
# Install Crontab Schedule Jobs
#
# Install crons from file first
echo "[Intializing crontab and adding crontabs from payload...]"
crontab payloads/crons
# Install cron for rkhunter
#echo "[Adding rkhunter to crontabs...]"
#crontab -l | { cat; echo "0 0 * * 0 rkhunter -c --sk"; } | crontab -
# TODO: what does rpm -V initscripts >> /var/log/initscripts.log do???
echo "[Adding rpm initscripts crontabs...]"
crontab -l | { cat; echo "0 0 * * 0 rpm -V initscripts >> /var/log/initscripts.log"; } | crontab -
# Install a cron to check that MySQL is running at all times
echo "[Adding MySQL status checking and restart to crontabs...]"
crontab -l | { cat; echo "* * * * * systemctl is-active --quiet mariadb || systemctl restart mariadb"; } | crontab -
# Install GitHub push and scp database backup to remote server
echo "[Adding GitHub and remote database backup to crontabs...]"
crontab -l | { cat; echo "1 0 * * * python ./root/VPS_deploy.py -githubbackup -p $1"; } | crontab -
crontab -l | { cat; echo "1 0 * * 1 python ./root/VPS_deploy.py -databasebackup -p $1"; } | crontab -
echo "[Adding a full scan of the WordPress Installation to crontabs...]"
crontab -l | { cat; echo "0 3 * * 2 clamscan -r -i /var/www/html/${githubuser[1]} -l /var/log/clamscan.log"; } | crontab -
echo "[Update the ClamScan virus signatures ...]"
crontab -l | { cat; echo "0 2 * * 2 freshclam"; } | crontab -
echo "[Finished adding crontabs to schedule...]"
echo "[Setting journalctl vacuume time ...]"
crontab -l | { cat; echo "1 0 1 * * journalctl --vacuum-time=30d"; } | crontab -
echo "[Finished setting journalctl vacuume time ...]"
#
# Prepare location for database backups
#
echo "[Adding MySQL backup location...]"
# Get the GitHub reponame to define the local database backup folder
while read -r -a githubuser
do
  # Eliminate comments
  if [[ ${githubuser[0]:0:1} != "#" && ! -z "${githubuser[0]}" ]]; then
    # Create the database backup destination folder and make mysqld permissions
    mkdir -p /var/www/backups/${githubuser[1]}
    chmod o+w /var/www/backups/${githubuser[1]}
  fi
done < payloads/github_userdata
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
# Install mod_evasive DDOS prevention
echo "[Installing additional Apache security packages...]"
yum install -y mod_evasive  mod_security
# Restart Apache
echo "[Restarting Apache...]"
systemctl restart httpd
# Show status of Apache
systemctl status httpd
# Move the payload and main script to the server, and run remotely
# TODO: use tool to autocomplete the requried input such as email address, etc. "2" into the certbot command
echo "[SSL certificate registered...]"
/bin/cp payloads/ssl.conf /etc/httpd/conf.d/ssl.conf
/bin/cp payloads/mod_evasive.conf /etc/httpd/conf.d/mod_evasive.conf
/bin/cp payloads/mod_security.conf /etc/httpd/conf.d/mod_security.conf
echo "[Moved configuration files to Apache...]"
echo "[Registering a SSL certificate with Let's Encrypt...]"
certbot --non-interactive --agree-tos --redirect --hsts --uir -m <your@emailaddress.com> --apache -d <default_site_URI> -d www.<default_site_URI>
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
#TODO Harden the httpd file permissions
#
#
#TODO Harden the mysql file permissions
#
#
#TODO Harden the other OS file permissions
#
#
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
      poweroff = 1
    fi
    if [ ${finish[0]} = "reboot" ] && [ ${finish[1]} = "1" ]; then
      reboot = 1
    fi
    if [ ${finish[0]} = "close" ] && [ ${finish[1]} = "1" ]; then
      # Close the payload
      close = 1
    fi
  fi
done < payloads/finish
# Use the variables to determine finish operations
if $poweroff = 1; then
  echo "[Powering off VPS server... image me!...]"
  poweroff
elif $reboot = 1; then
  echo "[Rebooting VPS server... see you soon!...]"
  reboot
elif $close = 1; then
  echo "[Closing the payload...]"
  python ./VPS_deploy.py -close -p $1
  echo "[Payload closed...]"
fi
