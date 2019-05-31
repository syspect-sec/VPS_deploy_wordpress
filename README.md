VPS Deploy WordPress
====================

Copyright (c) 2019 Ripple Software. All rights reserved.

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA

## Overview Description

VPS Deploy WordPress is to quickly deploy a CentOS 7 VPS as a web-server for a WordPress site. Steps to configure the payload are listed below including detailed descriptions of each element of VPS Deploy WordPress. Security is the focus of VPS Deploy WordPress.  VPS Deploy WordPress automatically clones a GitHub repository that contains your WordPress site onto the server, installs databases in MySQL, runs any additional scripts required, and sets up remote backups of the site changes and databases. VPS Deploy WordPress can also migrate your site's URL from your development environment to the live site URL, and vice versa.  You can also export the live site including any changes back to your local development environment to backup and maintain a feature testing development environment.

### Things you need to do:

1. Setup a Centos 7 VPS server with SSH access for root
2. Configure the 'serverdata' file in the root directory of VPS_deploy
3. Deploy the payload **VPS_deploy -remotedeploy**
4. Store the critical information output in a safe place
**WARNING - Don't forget to securely store the critical information output created by step 3**

### What VPS_deploy will do:

1. Configure and encrypt the payload
2. **VPS_deploy.py -remotedeploy** will prepare the VPS server to run VPS_deploy, move the encrypted payload and script to the server and then execute **VPS_deploy.py -deploy** script on the VPS server.
*TODO* does grub need to be configured for CentOS???
3. Non-root user(s) will be created and SSH for root user will be removed
4. A firewall will be installed, configured and installed as a service
5. **LAMP** stack will be installed, configured and installed as service
6. SELinux will be configured to allow SMTP, and PHP write access to the web root directory
7. **git** will be installed your GitHub repository cloned to the web root directory
8. The MySQL initialization script for the WordPress site will be modified for the live site URL.
9. An SSL certificate will be generated from Let's Encrypt Certificate Authority
10. Additional security packages **rkhunter** and **chkrootkit** will be installed and added to crontab for root
11. A database backup user will be added and backups will be added to crontab
12. Hardened configuration files for Apache, MySQL, and PHP will be copied into their appropriate locations
13. Permissions will be adjusted for the website files
14. Any additional MySQL or Bash scripts included in the GitHub repository will be executed
15. Apache will be started and the Apache configuration file will be encrypted
16. *Optional* the payload will be re-encrypted or server will be powered down so you can make an image of it.

*NOTE: script can be edited in payloads/VPS_deploy.sh*

## Detailed Payload Description

### Brief File Descriptions:

Here are brief overviews of all files required in VPS Deploy.  Configuration files also include commented instructions within the files.  

*Configuration Files*

**serverdata** ~ specify the IP address, domain-name, GitHub username and repository name,
root password, non-root username and password, and other config settings used configure the payload.  DNS name-server records must be set to point to that IP address in the configuration where you bought your domain name.

**payloads/additional_scripts** ~ any additional scripts that are contained in your GitHub repository or included in the payloads directory that you want to be run during the server setup.

**payloads/config** ~ an ssh config file (not being used now)

**payloads/crons** ~ any crons that you want added to the root user on the server.

**payloads/finish** ~ set what will VPS Deploy will do after it's finished. Options are
shutdown server, reboot server, and close payload

**payloads/github_userdata** ~ username and repository name for the GitHub repository that will be cloned into the web-root directory of the server.

**payloads/httpd.conf** ~ config file for Apache that will be copied into place on the server to replace the default one.

**payloads/jail.local** ~ Fail2Ban settings that will be copied into place on the server to replace the default one.

**payloads/http-get-dos.conf** ~ Fail2Ban configuration file to stop DOS using GET requests that will be copied into place on the server.

**payloads/http-post-dos.conf** ~ Fail2Ban configuration file to stop DOS using POST requests that will be copied into place on the server.

**payloads/my.cnf** ~ MySQL/MariaDB config file that will be copied into place on the server to replace the default one.

**payloads/mysql_scripts** ~ any additional MySQL scripts that you want to run to setup the web-application or server.  These can be located in the GitHub repository or in the payloads directory.  

**payloads/mysql_userdata** ~ list of usernames and passwords that will be created in MySQL/MariaDB.

**payloads/php.ini** ~ PHP config file that will be copied into place on the server to replace the default one.

**payloads/random_passwords** ~

**payloads/site_ownership** ~ any file ownership rules you want to be applied to the server.

**payloads/site_permissions** ~ any file permission rules you want to be applied to the server.

**payloads/site_permissions_open** ~ the file permissions you want to use when you need to open the web-application for editing files (-opendev flag).

**payloads/ssh_config** ~ the SSH config file that will be copied into place on the server to replace the default one.

**payloads/ssh_identity_file** ~

**payloads/sshd_config** ~ the SSHD config file that will be copied into place on the server to replace the default one.

**payloads/ssh.conf**

**payloads/userdata**

**payloads/V_host.conf** ~ the virtual host config file that will be copied into place on the server to replace the default one.  This file will be further altered by Let's Encrypt certbot during the installation of SSL/TLS certificates.

*Scripts*

**VPS_deploy.py** ~ the main script used to setup the server.

**VPS_remote.sh** ~ used for deploying the server remotely.  Initializes the server by installing some required packages, copying the payload onto the sever, and running the main script.  

**payloads/apache_config_locker.py** ~ used to encrypt/decrypt the Apache configuration file. This allows your Apache config file to contain environment variables that contain sensitive credentials and avoid any clear-text credentials on the server.

**payloads/VPS_apachectl.sh** ~ used to restart Apache.

**payloads/VPS_close.sh** ~ closes the permissions of the web-application to strict settings for improved security.

**payloads/VPS_open.sh** ~ opens the permissions of the web-application to allow editing of files by a non-root user.

**payloads/VPS_update_git.sh** ~

*Encryption Keys*

**payloads/id_rsa_github** ~ public key used to connect to GitHub account and clone the repository and to update GitHub repo from the VPS server once the package has been cloned.  This allows you to work on the application in a sandbox development environment and then update the live site once the changes have been tested and are ready to be pushed to the live site.

**payloads/id_rsa_github.pub** ~ public key used to connect to GitHub account.  **IMPORTANT** This key must have be added to your GitHub account to enable cloning of your repository.

*Log File*

**payloads/VPS_deploy.log** ~ main log file for VPS Deploy.

### Specific Configuration Details

*Non-root User Details*

**REQUIRED** You must add credentials to the userdata file.  Copy the two lines below and replace the username_default and password with your own username and password.  So, the file is simply two lines of text.  If you want other users added to the server, you can add lines to the file.

username_default dont_use_this_password

*SSH Configuration*

*Config Files*

A modified copy of ssh_config and sshd_config files have been added to required_files. You should check them out. They have been modified with some standard security concerns in mind such as:

1. **root** login has been disabled
2. Encryption cipher has been modified demand the most secure cipher available
3. Password based login has been disabled
4. A secure cipher-suite has been selected

*SSH Keys*

New SSH keys will be generated on the VPS for the new user and root SSH keys will be deleted. You will be provided with the server public key after VPS Deploy has finished and you try to connect to the server for the first time.

If you also want to replace the SSH public key that you used when created server, you should create a new RSA public key-pair on your and add the public key named id_rsa.pub to the require_files directory.  If a file named id_rsa.pub is found in the required_files directory and the file is not empty, that file will be placed into the /home/user/.ssh directory of the
non-root user created during setup.

*GitHub Keys*

VPS_deploy can download a GitHub repository to be automatically downloaded and installed into the web-root directory, you need to first create an RSA key-pair (ssh-keygen -t rsa -b 4096 -C "your_email@example.com").  Create the key named as id_rsa_github with no passphrase.  After the private and public key have been created, save copies of them in the require_files directory, and load the public key into your GitHub account. Log in, go to -> Settings -> SSH and GPG Keys -> New SSH Key.  Paste the public key into your account.    

*Apache Configuration*

A modified Apache config (httpd.conf) file for Centos is also located in the payloads directory. It has been modified for improved security to disabling indexing for all directories, forwarding all error messages to 500 error page to obfuscate the details of error messages. However, you will need to modify the file to allow access to any required asset/resource directories such as css files, javascript files, or images.  You may also want to otherwise configure the httpd.conf file as per your requirements.

Finally, the VPS_deploy script will encrypt the httpd.conf file after Apache has been started since it is not needed once Apache has been started.  The commands to decrypt the file to edit it and re-encrypt the file are included in the critical_information.txt file.

*PHP Configuruation*

A modified PHP config (php.ini) file for Centos is also located in the payloads directory. It has been modified for improved security by disabling some features of PHP that are not required for normal website operation such as remove file operations, remote PHP commands, ftp, etc. However, you will need to modify the file to allow access to any required asset/resource directories such as css files, javascript files, or images.  You may also want to otherwise configure the httpd.conf file as per your requirements.

*MySQL/MariaDB Configuration*

VPS_deploy.sh will automatically install and configure MySQL/MariaDB.  Standard security practices for MySQL are employed.  Also a backup user is created with only read permissions to all databases and a full database backup is added to the cron scheduler. Pay note to the fact that some special characters will break MySQL/MariaDB such as `$` and `!`.  These characters will not work when entered from a script.

## Other Configuration Details

*Let's Encrypt Certbot*

In the VPS_deploy.sh script, a SSL/TLS certificate is automatically installed onto the server for the domain specified in the serverdata file in the root directory of VPS_deploy as the line DomainName yourdomain.com.  The following flags/settings are currently used when obtaining a SSL/TLS certificate and more information can be obtained from the Let's Encrypt website (https://certbot.eff.org/docs/using.html).

-- redirect : all http requests are forwarded to https

-- hsts : https is used for all outgoing traffic forcing browsers to always use SSL/TLS for the domain.  

--uir : users browsers are forced to use https for all http content (such as images and links)

Finally, an certificate renewal is added to the cron scheduler.
