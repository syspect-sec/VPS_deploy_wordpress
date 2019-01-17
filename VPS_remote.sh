#!/bin/bash
# Move the payload and main script to the server, and run remotely
echo "[Moving payload and scripts to server...]"
while read -r -a sshdata
do
  # Eliminate all comment lines
  if [[ ${sshdata[0]:0:1} != "#" && ! -z "${sshdata[0]}" ]]; then
    if [ ${sshdata[0]} = "IP" ]; then
      # Scan the key into known_hosts
      ssh-keyscan -H ${sshdata[1]} >> /home/$USER/.ssh/known_hosts
      # Install the epel release
      ssh root@${sshdata[1]} 'yum install -y epel-release'
      echo "[Added epel-release repository to server...]"
      # Install python pip
      ssh root@${sshdata[1]} 'yum install -y python-pip'
      echo "[Added python-pip to server...]"
      # Upgrade pip
      ssh root@${sshdata[1]} 'pip install --upgrade pip'
      echo "[Added pip update to server...]"
      # Install python developer package
      ssh root@${sshdata[1]} 'yum install -y python-devel.x86_64'
      echo "[Added python development tools to server...]"
      # Install the C compiler
      ssh root@${sshdata[1]} 'yum install -y gcc'
      echo "[Added gcc to server...]"
      # Install pycrypto
      ssh root@${sshdata[1]} 'pip install -I pycrypto'
      echo "[Added pycrypto to server...]"
      echo "[Moving payload and script to server...]"
      # Move the payoad
      scp payload.zip root@${sshdata[1]}:~/
      # Move the serverdata file
      scp serverdata root@${sshdata[1]}:~/
      # Move the main script
      scp VPS_deploy.py root@${sshdata[1]}:~/
      # If the exit code was successfull
      if [ $? -eq 0 ]; then
          echo "[Payload and script moved to server...]"
          # Run the main script with the required password depending on purge flag
          if [ $2 = 1 ]
            then
              echo "[Issuing deploy and purge commands to remote server...]"
              ssh root@${sshdata[1]} "python VPS_deploy.py -deploy -purge -p $1 >> VPS_deploy.log"
              # Output to stdout, stderr, and VPS_deploy.log
              #ssh root@${sshdata[1]} "python VPS_deploy.py -deploy -purge -p $1 2>&1 | tee VPS_deploy.log"
              echo "[Deploy and purge command issued to remote server...]"
            else
              echo "[Issuing deploy command to remote server...]"
              ssh root@${sshdata[1]} "python VPS_deploy.py -deploy -p $1 >> VPS_deploy.log"
              # Output to stdout, stderr, and VPS_deploy.log
              #ssh root@${sshdata[1]} "python VPS_deploy.py -deploy -purge -p $1 2>&1 | tee VPS_deploy.log"
              echo "[Deploy command issued to remote server...]"
          fi
          # If the exit code was successfull
          if [ $? -eq 0 ]
            then
              echo "[Success]"
            else
              echo "[Could not successfully issue the command to the server...]"
              exit 1
          fi
      # If the return code from copying files was failed
      else
        echo "[Could not move files to server...]"
        exit 1
      fi
    fi
  fi
done < serverdata
echo "[VPS_deploy has been deployed on your remote server...]"
# TODO: adjust the ~/.ssh/config file to specify the ssd_config port on client
# Send a success exit code
exit 0
