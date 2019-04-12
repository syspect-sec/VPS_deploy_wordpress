#
# Install PHP 5.5
#
rpm -Uvh http://vault.centos.org/7.0.1406/extras/x86_64/Packages/epel-release-7-5.noarch.rpm
yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
yum --enablerepo=remi,remi-php56 -y install php php-common
yum --enablerepo=remi,remi-php56 -y install php-cli php-pdo php-mysql php-mysqlnd php-gd php-mcrypt php-xml php-simplexml php-zip
