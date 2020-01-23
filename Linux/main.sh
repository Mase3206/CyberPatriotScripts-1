#!/bin/bash
#MIT Licence 
#Copyright (c) Ethan Perry, Andy Lyu
unalias -a #Get rid of aliases
echo "unalias -a" >> ~/.bashrc
echo "unalias -a" >> /root/.bashrc
PWDthi=$(pwd)
if [ ! -d $PWDthi/referenceFiles ]; then
	echo "Please Cd into this script's directory"
	exit
fi
if [ "$EUID" -ne 0 ] ;
	then echo "Run as Root"
	exit
fi

#List of Functions:
#PasswdFun
#zeroUidFun
#rootCronFun
#apacheSecFun
#fileSecFun
#netSecFun
#aptUpFun
#aptInstFun (unused)
#deleteFileFun
#firewallFun
#sysCtlFun
#scanFun
#disableSuFun
#disableGuestFun

startFun()
{
	clear

	PasswdFun
	zeroUidFun
	rootCronFun
	apacheSecFun
	fileSecFun
	netSecFun
	aptUpFun
	#aptInstFun
	deleteFileFun
	firewallFun
	sysCtlFun
	scanFun
	disableSuFun
	passwdSecurityFun
	printf "\033[1;31mDone!\033[0m\n"
	additionalResourcesFun
}
cont(){
	printf "\033[1;31mI have finished this task. Continue to next Task? (Y/N)\033[0m\n"
	read contyn
	if [ "$contyn" = "N" ] || [ "$contyn" = "n" ]; then
		printf "\033[1;31mAborted\033[0m\n"
		exit
	fi
	clear
}
PasswdFun(){
	printf "\033[1;31mChanging Root's Password..\033[0m\n"
	
	echo "Make sure to change the unsecure passwords for the other users as well."
	
	#--------- Change Root Password ----------------
	passwd
	echo "i@mTh3on1y$upEru53r"
	cont
}
zeroUidFun(){
	printf "\033[1;31mChecking for 0 UID users...\033[0m\n"
	#--------- Check and Change UID's of 0 not Owned by Root ----------------
	touch /zerouidusers
	touch /uidusers

	cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

	if [ -s /zerouidusers ]
	then
		echo "There are Zero UID Users! I'm fixing it now!"

		while IFS='' read -r line || [[ -n "$line" ]]; do
			thing=1
			while true; do
				rand=$(( ( RANDOM % 999 ) + 1000))
				cut -d: -f1,3 /etc/passwd | egrep ":$rand$" | cut -d: -f1 > /uidusers
				if [ -s /uidusers ]
				then
					echo "Couldn't find unused UID. Trying Again... "
				else
					break
				fi
			done
			usermod -u $rand -g $rand -o $line
			touch /tmp/oldstring
			old=$(grep "$line" /etc/passwd)
			echo $old > /tmp/oldstring
			sed -i "s~0:0~$rand:$rand~" /tmp/oldstring
			new=$(cat /tmp/oldstring)
			sed -i "s~$old~$new~" /etc/passwd
			echo "ZeroUID User: $line"
			echo "Assigned UID: $rand"
		done < "/zerouidusers"
		update-passwd
		cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

		if [ -s /zerouidusers ]
		then
			echo "WARNING: UID CHANGE UNSUCCESSFUL!"
		else
			echo "Successfully Changed Zero UIDs!"
		fi
	else
		echo "No Zero UID Users"
	fi
	cont
}
rootCronFun(){
	printf "\033[1;31mChanging cron to only allow root access...\033[0m\n"
	
	#--------- Allow Only Root Cron ----------------
	#reset crontab
	crontab -r
	cd /etc/
	/bin/rm -f cron.deny at.deny
	echo root >cron.allow
	echo root >at.allow
	/bin/chown root:root cron.allow at.allow
	/bin/chmod 644 cron.allow at.allow
	cont
}
apacheSecFun(){
	printf "\033[1;31mSecuring Apache...\033[0m\n"
	#--------- Securing Apache ----------------
	a2enmod userdir

	chown -R root:root /etc/apache2
	chown -R root:root /etc/apache

	if [ -e /etc/apache2/apache2.conf ]; then
		echo "<Directory>" >> /etc/apache2/apache2.conf
		echo "        AllowOverride None" >> /etc/apache2/apache2.conf
		echo "        Order Deny,Allow" >> /etc/apache2/apache2.conf
		echo "        Deny from all" >> /etc/apache2/apache2.conf
		echo "</Directory>" >> /etc/apache2/apache2.conf
		echo "UserDir disabled root" >> /etc/apache2/apache2.conf
	fi

	systemctl restart apache2.service
	cont
}
fileSecFun(){
	printf "\033[1;31mSome automatic file inspection...\033[0m\n"
	#--------- Manual File Inspection ----------------
	cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > /tmp/listofusers
	echo root >> /tmp/listofusers
	
	#Replace sources.list with safe reference file (For Ubuntu 14 Only)
	cat $PWDthi/referenceFiles/sources.list > /etc/apt/sources.list
	apt-get update

	#Replace lightdm.conf with safe reference file
	cat $PWDthi/referenceFiles/lightdm.conf > /etc/lightdm/lightdm.conf

	#Replace sshd_config with safe reference file
	cat $PWDthi/referenceFiles/sshd_config > /etc/ssh/sshd_config
	/usr/sbin/sshd -t
	systemctl restart sshd.service

	#/etc/rc.local should be empty except for 'exit 0'
	echo 'exit 0' > /etc/rc.local

	printf "\033[1;31mFinished automatic file inspection. Continue to manual file inspection? (Y/N)\033[0m\n"
	read contyn
	if [ "$contyn" = "N" ] || [ "$contyn" = "n" ]; then
		exit
	fi
	clear

	printf "\033[1;31mSome manual file inspection...\033[0m\n"

	#Manual File Inspection
	nano /etc/resolv.conf #make sure if safe, use 8.8.8.8 for name server
	nano /etc/hosts #make sure is not redirecting
	visudo #make sure sudoers file is clean. There should be no "NOPASSWD"
	nano /tmp/listofusers #No unauthorized users

	cont
}
netSecFun(){ 
	printf "\033[1;31mSome manual network inspection...\033[0m\n"
	#--------- Manual Network Inspection ----------------
	lsof -i -n -P
	netstat -tulpn
	cont
}
aptUpFun(){
	printf "\033[1;31mUpdating computer...\033[0m\n"
	#--------- Update Using Apt-Get ----------------
	#apt-get update --no-allow-insecure-repositories
	apt-get update
	apt-get dist-upgrade -y
	apt-get install -f -y
	apt-get autoremove -y
	apt-get autoclean -y
	apt-get check
	cont
}
#aptInstFun(){
#	printf "\033[1;31mInstalling programs...\033[0m\n"
#	#--------- Download programs ----------------
#	apt-get install -y chkrootkit clamav rkhunter apparmor apparmor-profiles
#
#	#This will download lynis 2.4.0, which may be out of date
#	wget https://cisofy.com/files/lynis-2.5.5.tar.gz -O /lynis.tar.gz
#	tar -xzf /lynis.tar.gz --directory /usr/share/
#	cont
#}
deleteFileFun(){
	printf "\033[1;31mDeleting dangerous files...\033[0m\n"
	#--------- Delete Dangerous Files ----------------
	find / -name '*.mp3' -type f -delete
	find / -name '*.mov' -type f -delete
	find / -name '*.mp4' -type f -delete
	find / -name '*.avi' -type f -delete
	find / -name '*.mpg' -type f -delete
	find / -name '*.mpeg' -type f -delete
	find / -name '*.flac' -type f -delete
	find / -name '*.m4a' -type f -delete
	find / -name '*.flv' -type f -delete
	find / -name '*.ogg' -type f -delete
	find /home -name '*.gif' -type f -delete
	find /home -name '*.png' -type f -delete
	find /home -name '*.jpg' -type f -delete
	find /home -name '*.jpeg' -type f -delete
	cd / && ls -laR 2> /dev/null | grep rwxrwxrwx | grep -v "lrwx" &> /tmp/777s
	cont

	printf "\033[1;31m777 (Full Permission) Files : \033[0m\n"
	printf "\033[1;31mConsider changing the permissions of these files\033[0m\n"
	cat /tmp/777s
	cont
}
firewallFun(){
	apt-get install ufw
	ufw enable
}
sysCtlFun(){
	printf "\033[1;31mMaking Sysctl Secure...\033[0m\n"
	#--------- Secure /etc/sysctl.conf ----------------
	sysctl -w net.ipv4.tcp_syncookies=1
	sysctl -w net.ipv4.ip_forward=0
	sysctl -w net.ipv4.conf.all.send_redirects=0
	sysctl -w net.ipv4.conf.default.send_redirects=0
	sysctl -w net.ipv4.conf.all.accept_redirects=0
	sysctl -w net.ipv4.conf.default.accept_redirects=0
	sysctl -w net.ipv4.conf.all.secure_redirects=0
	sysctl -w net.ipv4.conf.default.secure_redirects=0
	sysctl -p
	cont
}
scanFun(){
	printf "\033[1;31mScanning for Viruses...\033[0m\n"
	#--------- Scan For Vulnerabilities and viruses ----------------

	#chkrootkit
	printf "\033[1;31mStarting CHKROOTKIT scan...\033[0m\n"
	chkrootkit -q
	cont

	#Rkhunter
	printf "\033[1;31mStarting RKHUNTER scan...\033[0m\n"
	rkhunter --update
	rkhunter --propupd #Run this once at install
	rkhunter -c --enable all --disable none
	cont
	
	#Lynis
	printf "\033[1;31mStarting LYNIS scan...\033[0m\n"
	cd /usr/share/lynis/
	/usr/share/lynis/lynis update info
	/usr/share/lynis/lynis audit system
	cont
	
	#ClamAV
	printf "\033[1;31mStarting CLAMAV scan...\033[0m\n"
	systemctl stop clamav-freshclam
	freshclam --stdout
	systemctl start clamav-freshclam
	clamscan -r -i --stdout --exclude-dir="^/sys" /
	cont
}

repoFun(){
	read -p "Please check the repo for any issues [Press any key to continue...]" -n1 -s
	nano /etc/apt/sources.list
	gpg /etc/apt/trusted.gpg > /tmp/trustedGPG
	printf "\033[1;31mPlease check /tmp/trustedGPG for trusted GPG keys\033[0m\n"
	cont
}

disableSuFun(){
	echo "Disabling 'sudo su'..."
	sed -i s/"orarom ALL=(ALL) ALL"/"orarom ALL = ALL, !/bin/sudo"/g /etc/ers
	
}

disableGuestFun(){
	echo "Disabling the guest account..."
	/usr/lib/lightdm/lightdm-set-defaults -l false
	
	cat /etc/lightdm/lightdm.conf >> /etc/lightdm/lightdm.conf.out
	if grep -q 'allow-guest=false' '/etc/lightdm/lightdm.conf'
		if [ -e /etc/lightdm/lightdm.conf ]; then
			echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
		fi
	fi
}

passwdSecurityFun(){
	apt-get install libpam-cracklib perl -y
	 cp /etc/pam.d/common-password /etc/pamd/common-password.backup
	
	if [ -e /etc/pam.d/common-password ]; then
		if grep -q "password required pam_cracklib.so retry=3 minlen=9 difok=3" /etc/pam.d/common-password; then
			echo "password required pam_cracklib.so retry=3 minlen=9 difok=3" >> /etc/pam.d/common-password
		fi
		
		if grep -q "password [success=1 default=ignore] pam_unix.so use_authtok nullok md5" /etc/pam.d/common-password; then
			echo "password [success=1 default=ignore] pam_unix.so use_authtok nullok md5" >> /etc/pam.d/common-password
		fi
		
		if grep -q "password requisite pam_deny.so" /etc/pam.d/common-password; then
			echo "password requisite pam_deny.so" >> /etc/pam.d/common-password
		fi
		
		if grep -q "password required pam_permit.so" /etc/pam.d/common-password; then
			echo "password required pam_permit.so"
		fi
		
	if [ -e /etc/login.defs ]; then
		perl -pi -e 's/PASS_MINLEN/PASS_MINLEN=9/g' /etc/login.defs
	fi
}

additionalResourcesFun(){
	echo "Here are some additional resources:"

	echo " "
	echo " "
	
	echo "WEBSITES FOR DEBIAN:"
	echo " "
	echo "debian.org/doc/manuals/debian-reference/ch04.en.html"
	echo "https://tinyurl.com/ryj7xcc"
	
	echo " "
	echo " "
		
	echo "WEBSITES FOR UBUNTU:"
	echo " "
	echo "https://tinyurl.com/ryj7xcc"
}

startFun