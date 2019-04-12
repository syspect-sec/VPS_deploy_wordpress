#
# Install PHP 7.1 and necessary extensions
#
rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm
yum install -y mod_php71w php71w-cli php71w-common php71w-gd php71w-mbstring php71w-mcrypt php71w-mysqlnd php71w-xml
