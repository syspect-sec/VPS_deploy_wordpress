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


# Get the site URI from the user configured serverdata file
def get_server_data_from_file(cwd):

    # Create an array to hold the serverdata
    server_data = {}

    # Open the serverdata file and find the server data
    with open(cwd + "/serverdata", "r") as serverdata_file:
        serverdata_array = serverdata_file.readlines()
    for line in serverdata_array:
        if line.strip()[0] is not "#":
            # Collect the IP from config file
            if line.split()[0] == "IP":
                server_data.update({'IP' : line.split()[1].strip()})
                print "Server IP: " + server_data['IP']
            # Collect the domain name from config file
            if line.split()[0] == "DomainName":
                server_data.update({'site_URI' : line.split()[1].strip()})
                print "Domain name: " + server_data['site_URI']
            # Collect the email address from config file
            if line.split()[0] == "EmailAddress":
                server_data.update({'admin_email' : line.split()[1].strip()})
                print "Admin email: " + server_data['admin_email']
            # Collect the root password from config file
            if line.split()[0] == "RootPassWord":
                server_data.update({'root_password' : line.split()[1].strip()})
                print "Root password: " + server_data['root_password']
            # Collect the non root password from config file
            if line.split()[0] == "NonRootPassword":
                server_data.update({'non_root_password' : line.split()[1].strip()})
                print "Non-root password: " + server_data['non_root_password']
            # Collect the non root username from config file
            if line.split()[0] == "NonRootUsername":
                server_data.update({'non_root_username' : line.split()[1].strip()})
                print "Non-root username: " + server_data['non_root_username']
            # Collect the non remote backup IP from config file
            if line.split()[0] == "RemoteBackupIP":
                server_data.update({'remote_backup_IP' : line.split()[1].strip()})
                print "Remote server IP " + server_data['remote_backup_IP']
            # Collect the PHP Version from config file
            if line.split()[0] == "PHPVersion":
                server_data.update({'PHP_version' : line.split()[1].strip()})
                print "PHP version " + server_data['PHP_version']
            # Collect the DB Application from config file
            if line.split()[0] == "DBApplication":
                server_data.update({'DB_app' : line.split()[1].strip()})
                print "Database Application " + server_data['DB_app']
            # Collect the Additional applications from config file
            if line.split()[0] == "AdditionalApplication":
                server_data['additional_app_array'] = []
                server_data.append('additional_app_array', line.split()[1].strip())
                print "Additional Application " + server_data['DB_app']
    # Check to see the serverdata has been modified
    if "IP" not in server_data or "site_URI" not in server_data or "admin_email" not in server_data:
        print "[You did not add your server config to the serverdata file...]"
        exit()

    # Set a false flag if there is no remote server IP
    if "remote_backup_IP" not in server_data:
        server_data.update({'remote_backup_IP' : False})

    # Print message to stdout
    print "[Server data has been parsed to get the site URI...]"
    # Return the dictionary with serverdata
    return server_data

# Get the github data from file
def get_github_data_from_file(payload_dirpath):

    # Create an array to hold the serverdata
    github_data = {}

    # Open the serverdata file and find the GitHub data
    with open(cwd + "/serverdata", "r") as serverdata_file:
        serverdata_array = serverdata_file.readlines()
    for line in serverdata_array:
        if line.strip()[0] is not "#":
            if line.split()[0] == "GitHubUser":
                github_data.update({"github_username" : line.split()[1]})
                print "GitHub username: " + github_data['github_username']
            if line.split()[0] == "GitHubRepo":
                github_data.update({"github_reponame" : line.split()[1]})
                print "GitHub repository name: " + github_data['github_reponame']

    if "github_username" not in github_data or "github_reponame" not in github_data:
        print "[You did add your GitHub info to the serverdata file...]"
        exit()
    # Print message to stdout
    print "[Server data has been parsed to get the GitHub data...]"
    # Return the dictionary with serverdata
    return github_data

# Collect any critical information required from the payload files
def collect_payload_critical_information(args_array):

    ## Include logger in the main function
    logger = logging.getLogger(args_array['app_name'])

    # Open the userdata file and read into array
    userdata_file = open("payloads/userdata", "r")
    userdata_contents_array = userdata_file.readlines()
    for line in userdata_contents_array:
        line = line.split().strip()
        if line[0] != "root":
            return line[0]

# Loads the payload and returns args_array
def load_payload(args_array):

    # Remove any default settings from the payload
    initialize_payload(args_array)
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

    # Get the non-root username to add to the critical information file
    non_root_username = collect_payload_critical_information(args_array)

    # Create a string to hold all the critical data
    critical_information_string = ""

    # Append to critical information string
    critical_information_string += "\n\nIMPORTANT: The payload will be erased after is is deployed so save the following information in a safe place."
    critical_information_string += "\n\nVPS_deploy payload password: " + args_array['command_args']['raw_password']
    critical_information_string += "\nSSH command: ssh " + non_root_username + '@' + args_array['site_IP']
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
                # Add non comments to the critical file output
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

# Migrate the files to be deployed at a new URL
def migrate_site_url(args_array):

    ## Include logger in the main function
    logger = logging.getLogger(args_array['app_name'])

    # Check if the infile is specified or use default
    if args_array['command_args']['infile'] == False:
        args_array['command_args']['infile'] = args_array['default_site_URI']
    # If there was a url included check if it has https and filter down to URI
    else:
        # Remove "https://", "http://", "www." from infile
        args_array['command_args']['infile'] = args_array['command_args']['infile'].replace("https://","")
        args_array['command_args']['infile'] = args_array['command_args']['infile'].replace("http://","")
        args_array['command_args']['infile'] = args_array['command_args']['infile'].replace("www.","")

    # Create infile variables for the URI, HTTPS_URL and WWW_URL
    args_array['infile_https_url'] = "https://" + args_array['command_args']['infile']
    args_array['infile_http_url'] = "http://" + args_array['command_args']['infile']
    args_array['infile_www_url'] = "www." + args_array['command_args']['infile']
    args_array['infile_uri'] = args_array['command_args']['infile']
    print "Infile set to: " +  args_array['infile_uri']

    # Remove "https://", "http://", "www." from outfile
    args_array['command_args']['outfile'] = args_array['command_args']['outfile'].replace("https://","")
    args_array['command_args']['outfile'] = args_array['command_args']['outfile'].replace("http://","")
    args_array['command_args']['outfile'] = args_array['command_args']['outfile'].replace("www.","")

    # Create outfile variables for the URI, HTTPS_URL and WWW_URL
    args_array['outfile_https_url'] = "https://www." + args_array['command_args']['outfile']
    # If the argument is set to force https for all site urls
    if args_array['force_ssl_during_migrate'] == True:
        args_array['outfile_http_url'] = "https://www." + args_array['command_args']['outfile']
    else:
        args_array['outfile_http_url'] = "http://www." + args_array['command_args']['outfile']
    args_array['outfile_www_url'] = "www." + args_array['command_args']['outfile']
    args_array['outfile_uri'] = args_array['command_args']['outfile']
    print "Outfile set to: " + args_array['outfile_uri']

    # Print message to stdout
    print "[Migrating WordPress site URL from " + args_array['infile_https_url'] +  " to " + args_array['outfile_https_url'] +  "...]"

    # Keep track of replacements in the file
    replacement_count = 0
    # Loop through all files
    for item in args_array["migrate_files_array"]:

        # Afix the full path to find the files to be migrated
        item = args_array['command_args']['wordpress_dirpath'] + item

        # For any directories in the list
        if os.path.isdir(item):
            for filename in os.listdir(item):
                if item[-1] != "/":
                    item = item + "/"
                # Call function to adjust file for migration
                replacement_count += migrate_single_file_url(args_array, item + filename)
        # For any files in the list
        if os.path.isfile(item):
            # Call function to adjust file for migration
            replacement_count += migrate_single_file_url(args_array, item)

    print "[Finished migration...]"
    # Print the total number of replacements found
    print "[ " + str(replacement_count) + " replacements were made...]"

# Recieves a filename and looks for infile and changes to outfile
def migrate_single_file_url(args_array, filename):

    # Include logger in the main function
    logger = logging.getLogger(args_array['app_name'])

    # Create an array to append the file data to
    migrated_file_contents_array = []
    # Get the base filename for output
    base_filename = filename.split("/")[-1]
    # Keep track of replacements in file
    replacement_count = 0

    # Print to stdout
    print "[Starting to migrate " + base_filename + "...]"

    # Open the file and replace the infile URL with the outfile
    with open(filename, "r") as infile:
        infile_contents = infile.readlines()

    # Go through the file and replace URI, HTTP_URL, and HTTP_URL
    for line in infile_contents:
        # If the line is empty
        if len(line.strip()) == 0:
            migrated_file_contents_array.append("\n")
        else:
            line = line.strip("\n")
            migrated_file_contents_array.append(line)

    # Rewrite the file arrray into the new file
    with open(filename, "w") as outfile:
        for line in migrated_file_contents_array:
            # Do not change comment lines
            if len(line.strip("\n")) != 0 and line.strip()[0] != "#":
                # Replace the URL's
                if args_array['infile_https_url'] in line:
                    #print "[Found https to be replaced...]"
                    line = line.replace(args_array['infile_https_url'],args_array['outfile_https_url'])
                    replacement_count += 1
                if args_array['infile_http_url'] in line:
                    #print "[Found http to be replaced...]"
                    line = line.replace(args_array['infile_http_url'],args_array['outfile_http_url'])
                    replacement_count += 1
                if args_array['infile_www_url'] in line:
                    #print "[Found www to be replaced...]"
                    line = line.replace(args_array['infile_www_url'],args_array['outfile_www_url'])
                    replacement_count += 1
                if args_array['infile_uri'] in line:
                    #print "[Found uri to be replaced...]"
                    line = line.replace(args_array['infile_uri'],args_array['outfile_uri'])
                    replacement_count += 1
            # Check if the line is a blank line
            if len(line.strip("\n")) == 0:
                outfile.write("\n")
            else:
                outfile.write(line + "\n")

    # Print to stdout
    #print "[Finished migrating file : " + base_filename + "...]"
    #print "[" + str(replacement_count) +  " replacements were found...]"
    # Return the replacement count to be tracked
    return replacement_count

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

# Remove any default settings from the payload
def initialize_payload(args_array):

    ## Include logger in the main function
    logger = logging.getLogger(args_array['app_name'])

    print "[Initializing the payload with configured serverdata settings...]"
    logger.info("[Initializing the payload with configured serverdata settings...]")

    # Open the .init_as file to see if default has already been overwritten
    with open(args_array['payload_init_filename'], "r") as init_as:
        init_as_contents = init_as.readlines()

    # If no remote backup IP has been included then set to default value
    if args_array['remote_backup_IP'] == False:
        args_array['remote_backup_IP'] = args_array['default_remote_backup_IP']

    # If the site has not been initialized yet
    if len(init_as_contents) == 0 or init_as_contents[0].strip() == "":
        print "[Deafult configuration detected...]"
        # Set the site config details to be replaced as the default
        args_array['current_site_IP'] = args_array['default_site_IP']
        args_array['current_site_URI'] = args_array['default_site_URI']
        args_array['current_admin_email'] = args_array['default_admin_email']
        args_array['current_remote_backup_IP'] = args_array['default_remote_backup_IP']
        # Set the current userdata to be replaced as the default
        args_array['current_root_password'] = args_array['default_root_password']
        args_array['current_non_root_password'] = args_array['default_non_root_password']
        args_array['current_non_root_username'] = args_array['default_non_root_username']
        # Set the GitHub username and repo name to be replaced as the default
        args_array['current_github_username'] = args_array['default_github_username']
        args_array['current_github_reponame'] = args_array['default_github_reponame']
    # Check if payload is still default or has been changed
    else:
        print "[Existing configuration detected...]"
        # Set the current site IP and URI to be replaced from the file
        args_array['current_site_IP'] = init_as_contents[0].strip()
        args_array['current_site_URI'] = init_as_contents[1].strip()
        args_array['current_admin_email'] = init_as_contents[2].strip()
        args_array['current_remote_backup_IP'] = args_array['remote_backup_IP']
        # Set the current userdata to be replaced as the default
        args_array['current_root_password'] = init_as_contents[3].strip()
        args_array['current_non_root_password'] = init_as_contents[4].strip()
        args_array['current_non_root_username'] = init_as_contents[5].strip()
        # Set the current GitHub username and repo name to be replaced from the file
        args_array['current_github_username'] = init_as_contents[6].strip()
        args_array['current_github_reponame'] = init_as_contents[7].strip()


    # Write the new serverdata configuration of payload into .init_as
    with open(args_array['payload_init_filename'], "w") as init_as:
        print "[Storing new configuration settings...]"
        init_as.write(args_array['site_IP'] + "\n")
        init_as.write(args_array['site_URI'] + "\n")
        init_as.write(args_array['admin_email'] + "\n")
        init_as.write(args_array['root_password'] + "\n")
        init_as.write(args_array['non_root_password'] + "\n")
        init_as.write(args_array['non_root_username'] + "\n")
        init_as.write(args_array['github_username'] + "\n")
        init_as.write(args_array['github_reponame'] + "\n")
        print "[Finished storing new configuration settings...]"

    # If the remote server has been specified in the serverdata file
    # replace it into the remote_serverdata file
    if "remote_backup_IP" in args_array:
        # Write the new serverdata configuration of payload into .init_as
        with open(args_array['payload_remote_serverdata_filename'], "w") as remote_serverdata:
            remote_serverdata.write(args_array['remote_backup_IP'])

    # Log and Stdout the server data changes to be made
    if args_array['current_site_IP'] != args_array['site_IP']:
        print "- Initializing the payload IP from " + args_array['current_site_IP'] + " to " + args_array['site_IP']
        logger.info("- Initializing the payload IP from " + args_array['current_site_IP'] + " to " + args_array['site_IP'])
    if args_array['current_site_URI'] != args_array['site_URI']:
        print "- Initializing the payload URI from " + args_array['current_site_URI'] + " to " + args_array['site_URI']
        logger.info("- Initializing the payload URI from " + args_array['current_site_URI'] + " to " + args_array['site_URI'])
    if args_array['current_admin_email'] != args_array['admin_email']:
        print "- Initializing the payload admin email from " + args_array['current_admin_email'] + " to " + args_array['admin_email']
        logger.info("- Initializing the payload admin email from " + args_array['current_admin_email'] + " to " + args_array['admin_email'])
    if args_array['current_remote_backup_IP'] != args_array['remote_backup_IP']:
        print "- Initializing the payload remote server IP from " + args_array['current_remote_backup_IP'] + " to " + args_array['remote_backup_IP']
        logger.info("- Initializing the payload remote server IP from " + args_array['current_remote_backup_IP'] + " to " + args_array['remote_backup_IP'])
    # Log and Stdout the userdata changes to be made
    if args_array['current_root_password'] != args_array['root_password'] or args_array['current_non_root_password'] != args_array['non_root_password']:
        print "- Initializing the payload userdata"
        logger.info("- Initializing the payload userdata")
    # Log and Stdout the GitHub changes to be made
    if args_array['current_github_username'] != args_array['github_username'] or args_array['current_github_reponame'] != args_array['github_reponame']:
        print "- Initializing the payload GitHub repo from " + args_array['current_github_username'] + ":" + args_array['current_github_reponame'] + " to " + args_array['github_username'] + ":" + args_array['github_reponame']
        logger.info("- Initializing the payload GitHub repo from " + args_array['current_github_username'] + ":" + args_array['current_github_reponame'] + " to " + args_array['github_username'] + ":" + args_array['github_reponame'])

    # Set a variable to count the number of replacements found
    replacement_count = 0

    # Rewrite the payload files with the new site IP and URL
    for key, values in args_array['initialize_files_array'].iteritems():
        print "- Modifying " + key + " type files"

        # If initializing the serverdata_file then create a replacement for the http redirect from the raw IP
        if key == "serverdata":
            current_IP_sub_array = args_array['current_site_IP'].replace("<","").replace(">","").split(".")
            new_IP_sub_array = args_array['site_IP'].split(".")
            args_array['current_httpd_redirect_IP'] = "^" + current_IP_sub_array[0] + "\\." + current_IP_sub_array[1] + "\\." + current_IP_sub_array[2] + "\\." + current_IP_sub_array[3] + "$"
            args_array['new_httpd_redirect_IP'] = "^" + new_IP_sub_array[0] + "\\." + new_IP_sub_array[1] + "\\." + new_IP_sub_array[2] + "\\." + new_IP_sub_array[3] + "$"
            print args_array['current_httpd_redirect_IP'] + " - " + args_array['new_httpd_redirect_IP']

        for item in values:
            print item
            # For any directories in the list
            if os.path.isdir(item):
                for filename in os.listdir(item):
                    if item[-1] != "/":
                        item = item + "/"
                    # Call function to adjust file for migration
                    replacement_count += initialize_single_file(key, args_array, item + filename)
            # For any files in the list
            if os.path.isfile(item):
                # Call function to adjust file for migration
                replacement_count += initialize_single_file(key, args_array, item)

    print "[ " + str(replacement_count) + " total replacements were found...]"

# Recieves a filename and looks for infile and changes to outfile
def initialize_single_file(key, args_array, filename):

    # Include logger in the main function
    logger = logging.getLogger(args_array['app_name'])

    # Create an array to append the file data to
    initialized_file_contents_array = []
    # Get the base filename for output
    base_filename = filename.split("/")[-1]
    # Keep track of replacements in file
    replacement_count = 0

    # Print to stdout
    print "[Starting to initialize " + base_filename + "...]"

    # Open the file and replace the existing values
    with open(filename, "r") as infile:
        infile_contents = infile.readlines()

    # Go through the file and replace URI, HTTP_URL, and HTTP_URL
    for line in infile_contents:
        # If the line is empty
        if len(line.strip()) == 0:
            initialized_file_contents_array.append("\n")
        else:
            line = line.strip("\n")
            initialized_file_contents_array.append(line)

    # Rewrite the file arrray into the new file
    with open(filename, "w") as outfile:
        for line in initialized_file_contents_array:
            # Do not change comment lines
            if line.strip() != "#":
                # Replace server data
                if key == "serverdata":
                    # Replace any modified instances of the current/default site IP address
                    if args_array['current_site_IP'] in line:
                        print "[Found IP to be replaced...]"
                        line = line.replace(args_array['current_site_IP'], args_array['site_IP'])
                        replacement_count += 1
                    # Replace any modified instances of the current/default site URI
                    if args_array['current_site_URI'] in line:
                        print "[Found URI to be replaced...]"
                        line = line.replace(args_array['current_site_URI'], args_array['site_URI'])
                        replacement_count += 1
                    # Replace any modified instances of the current/default admin email address
                    if args_array['current_admin_email'] in line:
                        print "[Found admin email to be replaced...]"
                        line = line.replace(args_array['current_admin_email'], args_array['admin_email'])
                        replacement_count += 1
                    # Replace any instances of the current/default http mod rewrite regex
                    if args_array['current_httpd_redirect_IP'] in line:
                        print "[Found IP regex to be replaced...]"
                        line = line.replace(args_array['current_httpd_redirect_IP'], args_array['new_httpd_redirect_IP'])
                        replacement_count += 1
                if key == "github_data":
                    # Replace any modified instances of the current/default GitHub userdata
                    if args_array['current_github_username'] in line:
                        print "[Found GitHub username to be replaced...]"
                        line = line.replace(args_array['current_github_username'], args_array['github_username'])
                        replacement_count += 1
                    # Replace any modified instances of the current/default GitHub repository name
                    if args_array['current_github_reponame'] in line:
                        print "[Found GitHub reponame to be replaced...]"
                        line = line.replace(args_array['current_github_reponame'], args_array['github_reponame'])
                        replacement_count += 1
                if key == "remote_serverdata":
                    # Replace any modified instances of the current/default remote backup IP
                    if args_array['current_remote_backup_IP'] in line:
                        print "[Found remote server IP to be replaced...]"
                        line = line.replace(args_array['current_remote_backup_IP'], args_array['remote_backup_IP'])
                        replacement_count += 1
            # Check if the line is a blank line
            if len(line.strip("\n")) == 0:
                outfile.write("\n")
            else:
                outfile.write(line + "\n")

    # Print to stdout
    print "[Finished initializing file : " + base_filename + "...]"
    print "[" + str(replacement_count) +  " replacements were found...]"
    # Return the replacement count to be tracked
    return replacement_count

# Prepares the arguments array for loading a payload or migrating a payload
def prepare_args_array(args_array):

    # Collect the serverdata from config file
    server_data = get_server_data_from_file(cwd)
    # Update the relevant entries in args_array
    # URI of the web-application to be deployed on the VPS
    args_array.update({"site_URI" : server_data['site_URI']})
    # IP of the server to host the site
    args_array.update({"site_IP" : server_data['IP']})
    # Admin email of the server to host the site
    args_array.update({"admin_email" : server_data['admin_email']})
    # Remote backup server IP
    args_array.update({"remote_backup_IP" : server_data['remote_backup_IP']})
    # Root password
    args_array.update({"root_password" : server_data['root_password']})
    # Non-root username
    args_array.update({"non_root_username" : server_data['non_root_username']})
    # Non-root password
    args_array.update({"non_root_password" : server_data['non_root_password']})
    # MySQL root password
    args_array.update({"mysql_root_password" : server_data['mysql_root_password']})
    # MySQL backup password
    args_array.update({"mysql_backup_password" : server_data['mysql_backup_password']})
    # Update the name of the sites_enabled file for Apache based on site_URI
    args_array["payload_filename_array"]["v_host_site_file"]["destination_path"] = "/etc/sites_enabled/" + server_data['site_URI'] + ".conf"

    # Github data is only available if payload is closed
    if is_payload_open(args_array):
        github_data = get_github_data_from_file(payload_dirpath)
        # Default location of the local WordPress site files
        default_local_site_dirpath = cwd + "/var/www/html/" + github_data['github_reponame'] + "/",
        # GitHub username and repo name
        args_array.update({"github_username" : github_data['github_username']})
        args_array.update({"github_reponame" : github_data['github_reponame']})

    # Return the updated args array
    return args_array

# Used to check if the payload is loaded or open
def is_payload_open(args_array):

    # If the payload directory exists, payload is open
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

        # First check if single command args are present
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

        # If not single command parse further
        else:
            # If the password flag is set then parse it
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
            # If there is no password argument
            elif "-p" not in args:
                # If the command is not migrate
                if "-migrate" not in args:
                    print "password please..."
                    return False

            # Look for infile in command args
            if "-if" in args:
                # Calculate position of -if argument
                infile_flag_position = args.index("-if")
                # Pop the flag off the array
                args.pop(infile_flag_position)
                # Look for the infile in the next position
                infile = args[infile_flag_position]
                # Pop the infile string out of the argument array
                args.pop(infile_flag_position)
                # Append the infile onto the command line argument array
                command_args.update({"infile" : infile})

            # Look for outfile in command args
            if "-of" in args:
                # Calculate position of -of argument
                outfile_flag_position = args.index("-of")
                # Pop the flag off the array
                args.pop(outfile_flag_position)
                # Look for the outfile in the next position
                outfile = args[outfile_flag_position]
                # Pop the outfile string out of the argument array
                args.pop(outfile_flag_position)
                # Append the outfile onto the command line argument array
                command_args.update({"outfile" : outfile})

            # Look for WordPress location in command args
            if "-wp" in args:
                # Calculate position of -of argument
                wordpress_dirpath_flag_position = args.index("-wp")
                # Pop the flag off the array
                args.pop(wordpress_dirpath_flag_position)
                # Look for the outfile in the next position
                wordpress_dirpath = args[wordpress_dirpath_flag_position]
                # Pop the outfile string out of the argument array
                args.pop(wordpress_dirpath_flag_position)
                # Append the outfile onto the command line argument array
                command_args.update({"wordpress_dirpath" : wordpress_dirpath})
                # Validate the WordPress directory exists
                if not os.path.isdir(command_args['wordpress_dirpath']):
                    print "The WordPress root directory you specified cannot be found..."
                    return False
                # Validate that it contains WordPress files
                else:
                    # Add a trailing "/" if not already
                    if command_args['wordpress_dirpath'][-1] != "/":
                        command_args['wordpress_dirpath'] = command_args['wordpress_dirpath'] + "/"
                    # Check for WordPress files in the directory
                    if not os.path.isfile(command_args['wordpress_dirpath'] + "wp-config.php"):
                        print "The WordPress root directory you specified does not seemt to contain WordPress..."
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

            # Check that purge is not set with illegal flags
            if command_args['purge']:
                if command_args['command'] in args_array['not_with_purge']:
                    print "Purge can only work with -deploy or -remotedeploy..."
                    return False

            # Check for outfile url if -migrate flag is set
            # and set infile to default if it is not set
            if command_args['command'] == "migrate":
                if "infile" not in command_args:
                    command_args.update({"infile" : False})
                if "outfile" not in command_args:
                    print "Destination URL must be be specified using the -of flag when migrating the site..."
                    return False
                if "wordpress_dirpath" not in command_args:
                    print "WordPress location must be be specified using the -wp flag when migrating the site..."
                    return False

            # Return the command args array
            return command_args

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
    argument_output += "Deploy usage : VPS_deploy.py [-load | -open | -deploy | -remotedeploy | -purge | -update] [-p <password>] | -backup <password>| -migrate -if <current url> -of <destination url>\n"
    argument_output += "Open/close the web-root for non-root read/write permissions: VPS_deploy [-opendev | -closedev]\n"
    argument_output += "-h, -help : print help menu\n"
    argument_output += "-load : encrypt and compress the payload to be deployed\n"
    argument_output += "-open : open the payload for editing\n"
    argument_output += "-deploy : deploy the payload to the VPS\n"
    argument_output += "-remotedeploy : move payload and script to remote server, deploy, then remove payload\n"
    argument_output += "-purge : deploy the payload and remove payload files\n"
    argument_output += "-update : update the GitHub repository (must be done locally on server)\n"
    argument_output += "-backup : backup the GitHub repository and move the databse backups to backup server\n"
    argument_output += "-migrate : migrate the WordPress site for another URL\n"
    argument_output += "-opendev : open the permissions on the web-root for editing\n"
    argument_output += "-closedev : close the permissions on the web-root for editing\n"
    argument_output += "-p <password> : password required to decrypt the data payload\n"
    argument_output += "-if <current url> : the current url to be migrate from (default is yoursite.com)\n"
    argument_output += "-of <destination url> : the new url the WordPress site will be hosted on\n"
    argument_output += "-wp <wordpress dirpath> : the dirpath of local WordPress site\n"
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

    # Prints the logo title
    print ascii_title()

    # Define some working directory variables
    cwd = os.getcwd()
    payload_dirpath = cwd + "/payloads/"

    ## Declare required variables for filepath and config filename
    args_array = {
        # VPS Deploy flags
        "app_name" : "VPS Deploy",
        "sandbox_mode" : True,
        "log_filename" : cwd + "/log",
        "cwd" : cwd + "/",
        # Default site URL in the vanilla version of the package
        "default_site_URI" : "<yoursite.com>",
        # Default IP address in the vanilla version of the package
        "default_site_IP" : "<123.456.78.9>",
        # Default remote backup server IP address in the vanilla version of the package
        "default_remote_backup_IP" : "<default_remote_backup_IP>",
        # Default admin emaill address in the vanilla version of the package
        "default_admin_email" : "<your@emailaddress.com>",
        # Default github username in the vanilla version of the package
        "default_github_username" : "<github_username>",
        # Default github repo username in the vanilla version of the package
        "default_github_reponame" : "<github_reponame>",
        # Default non-root username in the vanilla version of the package
        "default_non_root_username" : "<default_non_root_username>",
        # Default root password in the vanilla version of the package
        "default_root_password" : "<change_root_password>",
        # Default non-root user password in the vanilla version of the package
        "default_non_root_password" : "<change_non_root_password>",
        # Default MySQL root password in the vanilla version of the package
        "default_mysql_root_password" : "<default_mysql_root_password>",
        # Default MySQL backup password in the vanilla version of the package
        "default_mysql_backup_password" : "<default_mysql_backup_password>",
        # Allowed command line args
		"allowed_args_array" : ["-load", "-remotedeploy", "-deploy", "-open", "-p", "-opendev", "-closedev", "-purge", "-update", "-migrate", "-backup"],
        # Command args that are not allowed with purge
        'not_with_purge' : ["load", "open", "opendev", "closedev", "update", "migrate", "backup"],
        # Payload and required_files directory path
        "payload_dirpath" : payload_dirpath,
        # File to check if payload locked or not
        "payload_ready_filename" : ".passcheck",
        # File to check if payload is still default or has been init
        "payload_init_filename" : payload_dirpath + ".init_as",
        # Payload file containing userdata for VPS
        "payload_userdata" : payload_dirpath + "userdata",
        # File containing the remote backup IP address
        "payload_remote_serverdata_filename" : payload_dirpath + "remote_serverdata",
        # File containing the MySQL userdata
        "payload_mysql_userdata" : payload_dirpath + "mysql_userdata",
        # Filepath to zipped compressed payload
        "compressed_payload_filename" : "payload",
        # Filename of the main VPS_deploy script
        "VPS_deploy_script_deploy_filename" : "payloads/VPS_deploy.sh",
        # Filename of the script to move the payload to the remote server
        "VPS_deploy_script_remote_filename" : "VPS_remote.sh",
        # Filename of script to update GitHub repository
        "VPS_update_git_filename" : "payloads/VPS_update_git.sh",
        # Filename of script to update GitHub repository
        "VPS_backup_filename" : "payloads/VPS_remote_backup.sh",
        # Filename of script to open the permissions for dev
        "VPS_opendev_filename" : "VPS_open.sh",
        # Filename of script to close permissions
        "VPS_closedev_filename" : "VPS_close.sh",
        # Files to check during an initialization of the payload
        "initialize_files_array" : {
            # Files that have server data to be replaced
            "serverdata" : [
                cwd + "/payloads/httpd.conf",
                cwd + "/payloads/V_host.conf",
                cwd + "/payloads/remote_serverdata",
                cwd + "/payloads/VPS_deploy.sh",
                cwd + "/payloads/VPS_remote_backup.sh",
                cwd + "/payloads/userdata"
            ],
            # Files that have GitHub data to be replaced
            "github_data" : [
                cwd + "/payloads/github_userdata",
                cwd + "/payloads/httpd.conf",
                cwd + "/payloads/site_ownership",
                cwd + "/payloads/site_permissions",
                cwd + "/payloads/site_permissions_open",
                cwd + "/payloads/V_host.conf",
                cwd + "/payloads/VPS_deploy.sh"
            ],
            # Files that have remote backup server data to be replaced
            "remote_serverdata" : [
                cwd + "/payloads/remote_serverdata",
                cwd + "/payloads/ssh_identity_file"
            ],
            # Files that have MySQL data to be replaced
            "mysql_data" : [
                cwd + "/payloads/mysql_userdata"
            ]
        },
        # Files to check during a WordPress URL migration
        # These are relative to the WordPress
        "migrate_files_array" : [
            "extra_files/database/",
            "sitemap-news.xml"
        ],
        "force_ssl_during_migrate" : True,
        # Array of files that need to be executable
        "executable_files_array" : [
            "payloads/VPS_deploy.sh",
            "payloads/VPS_open.sh",
            "payloads/VPS_close.sh",
            "payloads/VPS_apachectl.sh",
            "payloads/apache_config_locker.py",
            "payloads/VPS_update_git.sh",
            "payloads/VPS_remote_backup.sh"
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
            "v_host_site_file" : { "required" : 0, "payload_filename" : payload_dirpath + "vhost.conf", "destination_path" : None},
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
        # Print the help output
        print_command_help_output()
        exit()

    # Main function post initial check starts here
    else:

        # If the VPS_deploy ready to be sent to the server
        if args_array['command_args']['command'] == "load":
            # Check if payload is open
            if is_payload_open(args_array):
                # Prepare the args array with site and repository data
                args_array = prepare_args_array(args_array)
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

            # Prepare the args array with site and repository data
            args_array = prepare_args_array(args_array)

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

            print "[Closing payload...]"
            # Close the payload
            load_payload(args_array)

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

        # If the command opendev then run script to change permissions
        elif args_array['command_args']['command'] == "backup":
            # Open the payload
            if is_payload_open(args_array) == False:
                print "[Opening payload...]"
                # Open the payload
                open_payload(args_array)

            # Check for the location of the script and run it
            if os.path.isfile("payloads/" + args_array['VPS_backup_filename']):
                subprocess.call("payloads/" + args_array['VPS_backup_filename'], shell=True)

            print "[Closing payload...]"
            # Close the payload
            load_payload(args_array)

        # If the command opendev then run script to change permissions
        elif args_array['command_args']['command'] == "migrate":

            # Open the payload
            if is_payload_open(args_array) == False:
                print "[Opening payload...]"
                # Open the payload
                open_payload(args_array)

            # Call the function to migrate the site urls
            migrate_site_url(args_array)
