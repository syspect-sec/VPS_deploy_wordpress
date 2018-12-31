#!/bin/bash
# Description:
# This file is used to assist deployment of a CentOS Linux VPS with LAMP stack.

# (1) Configure the package contents accordind to the README.md
# (2) Run python $ VPS_deploy.py -load -p <password>
# (2) Use secure copy `scp` to send to server
# (3) SSH into the server and run $ sudo VPS_deploy.py -deploy -p <password>

## Import Modules ##
import os
import sys
import logging
import time
import hashlib
from Crypto.Cipher import AES
import smtplib
import random
import string
import random
import traceback
import shutil
import subprocess
import zipfile
# import SecureString

# Returns the ASCII art title to print to stdout or file
def ascii_title():
    return """
____   ______________  _________      .___                   .__
\   \ /   /\______   \/   _____/    __| _/   ____   ______   |  |     ____    ___.__.
 \   Y   /  |     ___/\_____  \    / __ |  _/ __ \  \____ \  |  |    /  _ \  <   |  |
  \     /   |    |    /        \  / /_/ |  \  ___/  |  |_> > |  |__ (  <_> )  \___  |
   \___/    |____|   /_______  /  \____ |   \___  > |   __/  |____/  \____/   / ____|
                             \/        \/       \/  |__|                      \/
 __          __                     _   _____
 \\ \        / /                    | | |  __ \\
  \\ \\  /\\  / /    ___    _ __    __| | | |__) |  _ __    ___   ___   ___
   \\ \\/  \\/ /    / _ \\  | '__|  / _` | |  ___/  | '__|  / _ \\ / __| / __|
    \\  /\\  /    | (_) | | |    | (_| | | |      | |    |  __/ \\__ \\ \\__ \\
     \\/  \\/      \\___/  |_|     \\__,_| |_|      |_|     \\___| |___/ |___/
                                                                         """


# Loads the payload and returns args_array
def load_payload(args_array):
    # Store the critical information from the payload
    args_array = store_critical_information(args_array)
    # Create the payload
    create_payload(args_array)
    # Output the critical information from the payload
    output_critical_information(args_array)
    # Return args_array
    return args_array

# Stores the critical information as per user input
def store_critical_information(args_array):

    ## Include logger in the main function
    logger = logging.getLogger(args_array['app_name'])

    # Create a string to hold all the critical data
    critical_information_string = ""

    # Append to critical information string
    critical_information_string += "\n\nIMPORTANT: The payload will be erased after is is deployed so save the following information in a safe place."
    critical_information_string += "\n\nVPS_deploy payload password: " + args_array['command_args']['raw_password']
    critical_information_string += "\n\nOption A:"
    critical_information_string += "\n1. Copy (scp) payload.zip and VP_deplpy.py to your server"
    critical_information_string += "\n2. SSH into your VPS"
    critical_information_string += "\n3. Deploy (as root): $ python VPS_deploy.py -deploy -p " + args_array['command_args']['raw_password'] + "\n"
    critical_information_string += "\n\nOption B:"
    critical_information_string += "\n1. Remote deploy: $ python VPS_deploy.py -remotedeploy -p " + args_array['command_args']['raw_password'] + "\n"
    critical_information_string += "\n\nApache Config Locker:"
    critical_information_string += "\nApache configuration file has been encrypted.  Here are the commmands to decrypt it, or to restart Apache."
    critical_information_string += "\n1. Command to decrypt httpd config file: $ python apache_config_locker.py -open -p " + args_array['command_args']['raw_password']
    critical_information_string += "\n2. Command to encrypt httpd config file: $ python apache_config_locker.py -close -p " + args_array['command_args']['raw_password']
    critical_information_string += "\n3. Command to restart Apache and re-encrypt the config file: $ python apache_config_locker.py -restart -p " + args_array['command_args']['raw_password'] + "\n"

    try:
        for critical_item in args_array['critical_payload_information_files']:
            # Read the lines of the critical file into array
            with open(critical_item['filename'], "r") as critical_item_file:
                file_array = critical_item_file.readlines()

            # Check for the critical file that is a id_rsa_github
            if critical_item['filename'] == args_array['payload_dirpath'] + "id_rsa_github":
                if len(file_array) != 0:
                    critical_information_string +=  "\n" + critical_item['header'] + "\n"
            else:
                # Print the header
                critical_information_string += "\n" + critical_item['header'] + ": \n"
                #
                for line in file_array:
                    if line.strip()[:0] != "#":
                        critical_information_string += line

    except Exception as e:
        print traceback
    	# Collect the exception information
    	exc_type, exc_obj, exc_tb = sys.exc_info()
    	fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    	# Print the error
    	print 'Failed to add critical payload files: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
    	# Log error with creating filepath
    	logger.error('Failed add critical payload files: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
        exit()

    # Check if user wants critical information written to file
    write_critical_info_response = raw_input("Do you want to write critical information to file? (y or n):")
    if write_critical_info_response == "y" or write_critical_info_response == "Y":
        args_array["write_critical_info_response"] = True
        # Write the critical information to file
        with open(args_array['critical_information_filename'], "w") as critical_info_output_file:
            critical_info_output_file.write(ascii_title())
            critical_info_output_file.write(critical_information_string)
    else:
        args_array["write_critical_info_response"] = False
    # Print the critical_information_string to stdout
    args_array["critical_information_string"] = critical_information_string
    # Return the args array with the new information
    return args_array

# Print the critical information to stdout
def output_critical_information(args_array):

    print ascii_title()
    print args_array["critical_information_string"]
    # If the info was requested to file then print a message that it was stored
    if args_array['write_critical_info_response'] == True:
        print "[Critical Information was written to file -> " + args_array['critical_information_filename'] + " ]"

# Removes payload files from the server
def remove_payload(args_array):

    ## Include logger in the main function
    logger = logging.getLogger(args_array['app_name'])

    try:
        # Go through each file in payload and remove
        for key, value in args_array["payload_filename_array"].iteritems():
            os.remove(value["payload_filename"])

    except Exception as e:
        print traceback
    	# Collect the exception information
    	exc_type, exc_obj, exc_tb = sys.exc_info()
    	fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    	# Print the error
    	print 'Failed to remove payload files: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
    	# Log error with creating filepath
    	logger.error('Failed to remove payload files: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
    	return False

# Get script out of payload
def open_payload(args_array):

    ## Include logger in the main function
    logger = logging.getLogger(args_array['app_name'])

    print "[Opening payload...]"
    logger.info("[Opening payload...]")

    try:

        # Unzip the main payload located in required_files directory
        zip_file = zipfile.ZipFile(args_array['compressed_payload_filename'] + ".zip", 'r')
        # Check and create the payloads directory
        if not os.path.exists(args_array['payload_dirpath']):
            os.mkdir(args_array['payload_dirpath'])
        # Extract all into the payloads directory
        zip_file.extractall(args_array['payload_dirpath'])
        zip_file.close()
        os.remove(args_array["compressed_payload_filename"] + ".zip")

        # Use the main args_array passphrase to decrypt each file
        file_list = os.listdir(args_array['payload_dirpath'])
        for enc_file in file_list:
            enc_file = args_array['payload_dirpath'] + enc_file
            enc_file_output = enc_file.split("/")[-3] + "/" + enc_file.split("/")[-2] + "/" + enc_file.split("/")[-1]

            # Read encrypted contents into file
            with open(enc_file, "r") as payload_in_file:
                payload_content = payload_in_file.read()

            # Decrypt the file from encrypted format
    		IV = 16 * '\x00'
            mode = AES.MODE_CBC
            decryptor = AES.new(args_array['command_args']['key'], mode, IV=IV)
            payload_content = decryptor.decrypt(payload_content)

            # Check that the first line for confirmation of password
            # If the password confirmation is not correct, then return false
            if payload_content[0] != "*":
                print "your password is incorrect..."
                return False
            else:
                # Make an array to put passphrasess into
                payload_content_array = payload_content.splitlines()
                payload_content_cleaned = []

                # You may also want to remove whitespace characters like `\n` at the end of each line
                for line in payload_content_array:
                    # Ignore characters used to check password and pad the encryption
                    if line.strip() != "*" and line.strip() != len(line.strip()) * "@":
                        # Append the line to array
                        payload_content_cleaned.append(line)
                # Write the payload content into original random_passwords file
                with open(enc_file, "w") as payload_out_filename:
                    for line in payload_content_cleaned:
                        payload_out_filename.write(line + "\n")

                # Print and log success
                print "- Payload prepared: " + enc_file_output
                logger.info("- Payload prepared: " + enc_file_output)


        # Chmod the script files to be executable
        for ex_file in args_array['executable_files_array']:
            os.chmod(ex_file, 0700)

        print "[Payload opened...]"
        logger.info("[Payload opened...]")


    except Exception as e:
        print traceback
    	# Collect the exception information
    	exc_type, exc_obj, exc_tb = sys.exc_info()
    	fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    	# Print the error
    	print 'Failed to decrypt all files: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
    	# Log error with creating filepath
    	logger.error('Failed to decrypt all files: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
    	return False


# Checks for required files and encrypt the main payload.
def create_payload(args_array):

    ## Include logger in the main function
    logger = logging.getLogger(args_array['app_name'])

    print "[Starting to encrypt payload...]"
    logger.info("[Starting to encrypt payload...]")

    try:

        # Remove files that are not part of the payload
        for remove_file in args_array['remove_files']:
            if os.path.exists(args_array['payload_dirpath'] + remove_file):
                os.remove(args_array['payload_dirpath'] + remove_file)
                print "- Removed file: " + remove_file + " from payload"
                logger.info("- Removed file: " + remove_file + " from payload")

        # Check that all required files are there
        print "- Checking all required files are present"
        logger.info("- Checking all required files are present")
        for possible_file, item in args_array['payload_filename_array'].iteritems():

            # Get an item filename for output
            item_filename =  item['payload_filename'].split("/")[-3] + "/" + item['payload_filename'].split("/")[-2] + "/" + item['payload_filename'].split("/")[-1]

            if item['required'] == 1:
                if not os.path.exists(item['payload_filename']):
                    print "- Payload is missing a required file: " + item_filename
                    logger.info("- Payload is missing a required file: " + item_filename)
                    return False


        # Get a list of files that are present
        file_list = os.listdir(args_array['payload_dirpath'])
        # Encrypt all files that are present in the directory
        for plaintext_file in file_list:

            with open(args_array["payload_dirpath"] + plaintext_file, "r") as plaintext_in_file:
                file_array = plaintext_in_file.readlines()

            # Create a string to write to file
            # Add the character to check password
            data_string = "*\n"
            for item in file_array:
                data_string += item + "\n"
            data_string += "\n"

            # Encode data string to utf-8 to make sure it's common encoding
            data_string = data_string.encode('utf-8')

    		# Encrypt the data string to be written to file with padding
            IV = 16 * '\x00'
            mode = AES.MODE_CBC
            encryptor = AES.new(args_array['command_args']['key'], mode, IV=IV)
            file_data_in_ciphertext = encryptor.encrypt(data_string + ((16 - len(data_string)%16) * "@"))

            # Write data to file
            with open(args_array["payload_dirpath"] + plaintext_file, "w") as payload_out_filename:
                # Write the encrypted data to file
                payload_out_filename.write(file_data_in_ciphertext)

            print "- Payload file: " + plaintext_file + " encrypted..."
            logger.warning("- Payload is missing a required file: " + item_filename)


        # Zip the payload directory
        shutil.make_archive(args_array['compressed_payload_filename'], 'zip', args_array['payload_dirpath'])
        # Remove the payloads unencrypted directory
        shutil.rmtree(args_array['payload_dirpath'])

        # Print message and log
        print "[Payload loaded and ready for deployment... ]"
        logger.info("[Payload loaded and ready for deployment... ]")

    except Exception as e:
        print traceback
		# Collect the exception information
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		# Print the error
        print 'Failed to encrypt the payload: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
        # Log error with creating filepath
        logger.error('Failed to encrypt the payload: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
        return False

# Used to check if the payload is loaded or open
def is_payload_open(args_array):

    if os.path.exists(args_array['payload_dirpath']):
        return True
    else:
        return False

# Parses the command argument sys.arg into command set,
# also encode password from command line and append to
# command_args for use
def build_command_arguments(args, args_array):

	## Include logger in the main function
    logger = logging.getLogger(args_array['app_name'])

    try:
        # Create an array to store modified command line arguemnts
        command_args = {}

        # Pop off the first element of array because it's the application filename
        args.pop(0)

        # First check if opendev or closedev arg issued
        if len(args) == 1:
            if "-opendev" in args:
                # Return the command args array
                command_args['command'] = args[0].replace('-', '')
                return command_args
            elif "-closedev" in args:
                # Return the command args array
                command_args['command'] = args[0].replace('-', '')
                return command_args
            else: return False

        # If not opendev or closedev there needs to be 3 or 4 arguments
        elif len(args) >= 3 and len(args) <=4:
            if "-p" in args:
                # Calculate position of -p argument
                password_flag_position = args.index("-p")
                # Pop the flag off the array
                args.pop(password_flag_position)
                # Look for the password in the next position
                raw_password = args[password_flag_position]
                # Pop the password string out of the argument array
                args.pop(password_flag_position)
                # encrypt the raw_password into the form used for encryption
                key = hashlib.sha256(raw_password).digest()
                # Append the raw password onto the command line argument array
                command_args.update({"raw_password" : raw_password})
                # Append the key back onto the end of the command line arguement array
                command_args.update({"key" : key})
            # If there is no password argument, then the command line is failed
            elif "-p" not in args:
                print "password please..."
                return False

            # For loop to modify elements and strip "-"
            for item in args:
                if item in args_array['allowed_args_array']:
                    # Check for purge flag
                    if item == "-purge":
                        command_args['purge'] = True
                    else:
                        command_args['purge'] = False
                        item = item.replace('-', '')
                        command_args.update({"command" : item})
                else:
                    print "Command line args failed..."
                    return False

            # Check that purge is not set with load or open flags
            if command_args['purge']:
                if command_args['command'] in args_array['not_with_purge']:
                    print "Purge can only work with -deploy or -remotedeploy..."
                    return False

            # Return the command args array
            return command_args

        # There are an incorrect number of arguments
        else:
            return False

    except Exception as e:
        # Collect the exception information
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        # Print the error
        print 'Failed to build command arguments: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
        # Log error with creating filepath
        logger.error('Failed to build command arguments: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
        return False

# Build the output for command line instructions
def print_command_help_output():
    argument_output = "Notice : You need to run this script as root.\n"
    argument_output += "Notice : -opendev & -closedev do not require -p <password>.  All other commands do.\n"
    argument_output += "Deploy usage : VPS_deploy.py [-load | -open | -deploy | -remotedeploy | -purge | -update] [-p <password>] \n"
    argument_output += "Open/close the web-root for non-root read/write permissions: VPS_deploy [-opendev | -closedev]"
    argument_output += "-h, -help : print help menu\n"
    argument_output += "-load : encrypt and compress the payload to be deployed\n"
    argument_output += "-open : open the payload for editing\n"
    argument_output += "-deploy : deploy the payload to the VPS. \n"
    argument_output += "-remotedeploy : move payload and script to remote server, deploy, then remove payload\n"
    argument_output += "-purge : deploy the payload and remove payload files.\n"
    argument_output += "-update : update the GitHub repository (must be done locally on server).\n"
    argument_output += "-opendev : open the permissions on the web-root for editing\n"
    argument_output += "-closedev : close the permissions on the web-root for editing\n"
    argument_output += "-p <password> : password required to decrypt the data payload\n"
    print argument_output

# Setup logging
def setup_logger(args_array):

    logger = logging.getLogger(args_array['app_name'])
    log_handler = logging.FileHandler(args_array['log_filename'])
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)


## Main Function Starts Here ##
if __name__ == '__main__':

    # Define some working directory variables
    cwd = os.getcwd()
    payload_dirpath = cwd + "/payloads/"
    site_URI = "elaan.com.tw"

    ## Declare required variables for filepath and config filename
    args_array = {
        # VPS Deploy flags
        "app_name" : "VPS Deploy",
        "sandbox_mode" : True,
        "log_filename" : "log",
        "cwd" : cwd + "/",
		# URI of the web-application to be deployed on the VPS
        "site_URI" : site_URI,
        # Allowed command line args
		"allowed_args_array" : ["-load", "-remotedeploy", "-deploy", "-open", "-p", "-opendev", "-closedev", "-purge", "-update"],
        # Command args that are not allowed with purge
        'not_with_purge' : ["load", "open", "opendev", "closedev", "update"],
        # Payload and required_files directory path
        "payload_dirpath" : payload_dirpath,
        # File to check if payload locked or not
        "payload_ready_filename" : ".passcheck",
        # Filepath to zipped compressed payload
        "compressed_payload_filename" : "payload",
        # Filename of the main VPS_deploy script
        "VPS_deploy_script_deploy_filename" : "payloads/VPS_deploy.sh",
        # Filename of the script to move the payload to the remote server
        "VPS_deploy_script_remote_filename" : "VPS_remote.sh",
        # Filename of script to update GitHub repository
        "VPS_update_git_filename" : "payloads/VPS_update_git.sh",
        # Filename of script to open the permissions for dev
        "VPS_opendev_filename" : "VPS_open.sh",
        # Filename of script to close permissions
        "VPS_closedev_filename" : "VPS_close.sh",
        # Array of files that need to be executable
        "executable_files_array" : [
            "payloads/VPS_deploy.sh",
            "payloads/VPS_open.sh",
            "payloads/VPS_close.sh",
            "payloads/VPS_apachectl.sh",
            "payloads/apache_config_locker.py",
            "payloads/VPS_update_git.sh",
        ],
        # Array of all possible files in required_files
        "payload_filename_array" : {
            # GitHub config details and keys
            "github_private_key" : { "required" : 0, "payload_filename" : payload_dirpath + "id_rsa_github", "destination_path" : "~/.ssh/id_rsa_github"},
            "github_public_key" : { "required" : 0, "payload_filename" : payload_dirpath + "id_rsa_github.pub", "destination_path" : "~/.ssh/id_rsa_github.pub"},
            "passphrases_list" : { "required" : 0, "payload_filename" : payload_dirpath + "random_passwords", "destination_path" : None},
            "new_server_ssh_private_key" : { "required" : 0, "payload_filename" : payload_dirpath + "id_rsa", "destination_path" : "~/.ssh/id_rsa"},
            "new_server_ssh_public_key" : { "required" : 0, "payload_filename" : payload_dirpath + "id_rsa.pub", "destination_path" : "~/.ssh/id_rsa.pub"},
            "site_permissions" : { "required" : 1, "payload_filename" : payload_dirpath + "site_permissions", "destination_path" : None},
            "userdata" : { "required" : 1, "payload_filename" : payload_dirpath + "userdata", "destination_path" : None},
            "apache_config_file" : { "required" : 1, "payload_filename" : payload_dirpath + "httpd.conf", "destination_path" : "/etc/httpd/conf/httpd.conf"},
            "v_host_site_file" : { "required" : 0, "payload_filename" : payload_dirpath + "vhost.conf", "destination_path" : "/etc/sites_enabled/" + site_URI + ".conf"},
            "php_config_file" : { "required" : 1, "payload_filename" : payload_dirpath + "php.ini", "destination_path" : "/etc/php.ini"},
            "ssh_config_file" : { "required" : 1, "payload_filename" : payload_dirpath + "ssh_config", "destination_path" : "/etc/ssh/ssh_config"},
            "sshd_config_file" : { "required" : 1, "payload_filename" : payload_dirpath + "sshd_config", "destination_path" : "/etc/ssh/sshd_config"}
        },
        # Array of critical payoad filenames and headers for printing to stdout
        "critical_payload_information_files" : [
            { "header" : "VPS User Passwords", "filename" : payload_dirpath + "userdata" },
            { "header" : "VPS Mysql User Passwords", "filename" : payload_dirpath + "mysql_userdata" },
            { "header" : "You have included a SSH key for GitHub.  Please remember to upload the public key to your GitHub user account.", "filename" : payload_dirpath + "id_rsa_github" }
        ],
        # File to write critical information to if requested
        "critical_information_filename" : "critical_information.txt",
        # Array of files to be removed before payload is encrypted
        "remove_files" : [
            ".DS_Store"
        ]
	}

    ## Run function to setup logger
    setup_logger(args_array)
    ## Include logger in the main function
    logger = logging.getLogger(args_array['app_name'])

    ## Perform analysis of command line args into another array
    args_array['command_args'] = build_command_arguments(sys.argv, args_array)

    ## Check return from command line arg bulder and if no command line args
    # If command_args failed, print message
    if args_array['command_args'] == False:
        # Prints the logo title
        print ascii_title()
        # Print the help output
        print_command_help_output()

    # Main function post initial check starts here
    else:
        # Prints the logo title
        print ascii_title()

        # If the VPS_deploy ready to be sent to the server
        if args_array['command_args']['command'] == "load":
            # Check if payload is open
            if is_payload_open(args_array):
                # Load the payload
                args_array = load_payload(args_array)
            else:
                print "[Payload already loaded for deployment]"

        # If the VPS_deploy ready to be sent to the server
        elif args_array['command_args']['command'] == "open":
            # Check if payload is open
            if is_payload_open(args_array):
                print "[Payload already open for editing...]"
            else:
                # Get all files out of payload
                open_payload(args_array)

        # If the VPS_deploy is on the server and ready to be deployed
        elif args_array['command_args']['command'] == "deploy":
            # Check if the payload is open
            if is_payload_open(args_array) == False:
                print "[Opening Payload...]"
                # Open the payload
                open_payload(args_array)

            print "[Deploying payload locally...]"
            # Deploy payload
            if args_array['command_args']['purge'] == True:
                # Run the configured payload as bash script with flag set to deploy
                subprocess.call(args_array['VPS_deploy_script_deploy_filename'] + " " + args_array['command_args']['raw_password'] + " 1  >> VPS_deploy.log", shell=True)
                # Output to stdout, stderr, and VPS_deploy.log
                #subprocess.call(args_array['VPS_deploy_script_deploy_filename'] + " " + args_array['command_args']['raw_password'] + " 1  2>&1 | tee VPS_deploy.log", shell=True)
            else:
                # Run the configured payload as bash script
                subprocess.call(args_array['VPS_deploy_script_deploy_filename'] + " " + args_array['command_args']['raw_password'] + " 0 >> VPS_deploy.log", shell=True)
                # Output to stdout, stderr, and VPS_deploy.log
                #subprocess.call(args_array['VPS_deploy_script_deploy_filename'] + " " + args_array['command_args']['raw_password'] + " 0 2>&1 | tee VPS_deploy.log", shell=True)

            # Close the payload
            if is_payload_open(args_array) == False:
                print "[Opening Payload...]"
                # Load the payload
                args_array = load_payload(args_array)

        # If VPS_deploy is on the client and ready to be deployed
        elif args_array['command_args']['command'] == "remotedeploy":

            # Check if payload is open
            if is_payload_open(args_array):
                print "[Payload not loaded for deployment...loading payload...]"
                # Load the payload
                args_array = load_payload(args_array)

            # Remote deploy
            if args_array['command_args']['purge'] == True:
                print "[Deploying payload to remote server with purge...]"
                # Move payload to server, run, and remove the payload
                subprocess.call("./" + args_array['VPS_deploy_script_remote_filename'] + " " + args_array['command_args']['raw_password'] + " 1" , shell=True)
            else:
                print "[Deploying payload to remote server...]"
                # Move payload to server, and run
                subprocess.call("./" + args_array['VPS_deploy_script_remote_filename'] + " " + args_array['command_args']['raw_password'] + " 0" , shell=True)

            # Open the payload again
            if is_payload_open(args_array) == False:
                print "[Re-opening local payload...]"
                # Open the payload
                open_payload(args_array)

        # If the command update then run script to update the GitHub repository
        elif args_array['command_args']['command'] == "update":
            # Open the payload again
            if is_payload_open(args_array) == False:
                print "[Opening payload...]"
                # Open the payload
                open_payload(args_array)

            if os.path.isfile(args_array['VPS_update_git_filename']):
                subprocess.call("./" + args_array['VPS_update_git_filename'], shell=True)
            else:
                print "[Could not locate the script to update GitHub repository...]"

        # If the command opendev then run script to change permissions
        elif args_array['command_args']['command'] == "opendev":
            # Check for the location of the script and run it
            if os.path.isfile("payloads/" + args_array['VPS_opendev_filename']):
                subprocess.call("payloads/" + args_array['VPS_opendev_filename'], shell=True)
            elif os.path.isfile(args_array['VPS_opendev_filename']):
                subprocess.call("./" + args_array['VPS_opendev_filename'], shell=True)
            else:
                print "[Could not locate the script to open web-directory permissions...]"

        # If the command opendev then run script to change permissions
        elif args_array['command_args']['command'] == "closedev":
            # Check for the location of the script and run it
            if os.path.isfile("payloads/" + args_array['VPS_closedev_filename']):
                subprocess.call("payloads/" + args_array['VPS_closedev_filename'], shell=True)
            elif os.path.isfile(args_array['VPS_closedev_filename']):
                subprocess.call("./" + args_array['VPS_closedev_filename'], shell=True)
            else:
                print "[Could not locate the script to close web-directory permissions...]"
