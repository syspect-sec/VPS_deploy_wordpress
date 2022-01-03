#!/usr/bin/env python
# Apache Config Locker
# Description--
# This script will stop apache if it is already started, decrypt the config file
# and then restart apache and finally re-encrypt the config file.  The purpose is
# to allow a server to maintain important passwords and API keys out of cleartext.
# The Apache config file should therefore load a list of passwords into environment.
## Import Modules ##
import os
import sys
import logging
import time
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import smtplib
import subprocess

# Print the ascii header
def print_ascii_header():
 print """
  ____ ____   ____    __ __ __   ___         __  ___  ____  _____ ____  ____      _      ___     __ __  _   ___ ____
 /    |    \ /    |  /  |  |  | /  _]       /  ]/   \|    \|     |    |/    |    | |    /   \   /  |  |/ ] /  _|    \\
|  o  |  o  |  o  | /  /|  |  |/  [_       /  /|     |  _  |   __||  ||   __|    | |   |     | /  /|  ' / /  [_|  D  )
|     |   _/|     |/  / |  _  |    _]     /  / |  O  |  |  |  |_  |  ||  |  |    | |___|  O  |/  / |    \|    _|    /
|  _  |  |  |  _  /   \_|  |  |   [_     /   \_|     |  |  |   _] |  ||  |_ |    |     |     /   \_|     |   [_|    \\
|  |  |  |  |  |  \     |  |  |     |    \     |     |  |  |  |   |  ||     |    |     |     \     |  .  |     |  .  \\
|__|__|__|  |__|__|\____|__|__|_____|     \____|\___/|__|__|__|  |____|___,_|    |_____|\___/ \____|__|\_|_____|__|\_|
"""

## Import data from file_list
def decrypt_config(args_array):
	## Include logger in the main function
	logger = logging.getLogger(args_array["app_name"])
	# Create an array to hold the original file contents
	original_file_content_array = []
	# Set the key, and paths
	key = args_array['command_args']['key']
	config_path_and_filename = args_array['config_path_and_filename']
	encrypted_path_and_filename = args_array['encrypted_path_and_filename']
	# Print message to stdout
	print '[Starting to decrypt config file...]'
	# Log to file
	logger.info('[Starting to decrypt config file...]')
	try:
		# Collect the encrypted config file data
		with open(encrypted_path_and_filename, "r") as encrypted_config_file:
			encrypted_config_content = encrypted_config_file.read()
		# Decrypt the file from encrypted format
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		decryptor = AES.new(key, mode, IV=IV)
		original_config_content = decryptor.decrypt(encrypted_config_content)
		# Break decrypted string into array
		original_config_content = original_config_content.splitlines()
		# Check that the first line is the password correct confirmation
		# If the password confirmation is not correct, then return false
		if original_config_content[0] != "@@@@":
			print "Incorrect Password!"
			logger.warning("Incorrect Password!")
			return False
		else:
			# Print message to stdout
			print '[Encrypted config file contents validated...]'
			# Log to file
			logger.info('[Encrypted config file contents validated...]')
		# Append each item in array to and remove validation line and padding
		for item in original_config_content:
			# Check for the character used to pad the encryption
			if item.endswith("@") or item.strip() == "":
				pass
			else:
				original_file_content_array.append(item + "\n")
		# Write the array to the original config filepath
		with open(config_path_and_filename, "w") as original_config_file:
			for item in original_file_content_array:
				original_config_file.write(item)
		# Return the array
		# Print message to stdout
		print '[Config file decrypted to successfully...]'
		# Log to file
		logger.info('[Config file decrypted to successfully...]')
		# Return success message
		return True
	# If there was an error
	except Exception as e:
		# Collect the exception information
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		# Print the error
		print 'Failed to decrypt the contents of the config file: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		# Log error with creating filepath
		logger.error('Failed to decrypt the contents of the config file: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		# Return failed message
		return False

## Parses the command argument sys.arg into command set, also encrypt password for use
def build_command_arguments(argument_array, args_array):
	## Include logger in the main function
	logger = logging.getLogger(args_array["app_name"])
	try:
		# Create an array to store modified command line arguemnts
		command_arg = {}
		# If the help menu is requested
		if "-h" in argument_array or "-help" in argument_array:
			print "here"
			command_arg.update({"command" : "h"})
			return command_arg
		# Check that the argument array is proper length (4)
		if len(argument_array) != 4:
			return False
		# Pop off the first element of array because it's the application filename
		argument_array.pop(0)
		# find the password argument and take the password part and encrypt, attach as the second argument
		if "-p" in argument_array:
			# Calculate position of -p argument
			password_flag_position = argument_array.index("-p")
			# Pop the flag off the array
			argument_array.pop(password_flag_position)
			# Look for the password in the next position
			raw_password = argument_array[password_flag_position]
			# Pop the password string out of the argument array
			argument_array.pop(password_flag_position)
			# encrypt the raw_password into the form used for encryption
			key = hashlib.sha256(raw_password).digest()
			# Append the key back onto the end of the command line arguement array
			command_arg.update({"key" : key})
		# If there is no password argument, then the command line is failed
		else:
			return False
		# For loop to modify elements and strip "-"
		for item in argument_array:
			# Check that the argument is allowed
			if item in args_array['allowed_args_array']:
				item = item.replace('-', '')
				command_arg.update({"command" : item})
			# If argument not in allowed_args_array then return false
			else:
				return False
		# The final array should always be list of length 2
		if len(command_arg) != 2:
			return False
		# Return the modified array of length is proper
		else:
			return command_arg
	except Exception as e:
		# Collect the exception information
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		# Print the error
		print 'Failed to build command arguments: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		# Log error with creating filepath
		logger.error('Failed to build command arguments: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

# Iteration of bytes of each file
def hash_bytestr_iter(bytesiter, hasher, ashexstr=False):
    for block in bytesiter:
        hasher.update(block)
    return (hasher.hexdigest() if ashexstr else hasher.digest())
def file_as_blockiter(afile, blocksize=65536):
    with afile:
        block = afile.read(blocksize)
        while len(block) > 0:
            yield block
            block = afile.read(blocksize)

# Encrypt the configuration file
def encrypt_config(args_array):
	## Include logger in the main function
	logger = logging.getLogger(args_array["app_name"])
	# Set the key, and paths
	key = args_array['command_args']['key']
	config_path_and_filename = args_array['config_path_and_filename']
	encrypted_path_and_filename = args_array['encrypted_path_and_filename']
	# Print message to stdout
	print '[Starting to encrypt config file...]'
	# Log to file
	logger.info('[Starting to encrypt config file...]')
	# Use the config_path_and_filename to find the file and store in enncrypted_path_and_filename
	try:
		# Open the decrypted config file and read into array
		with open(config_path_and_filename, "r") as config_file:
			config_file_array = config_file.readlines()
		# Create a string to write to file
		# First add the indicator for the password check
		data_string = "@@@@\n"
		# Add each line of the array
		for item in config_file_array:
			data_string += item + "\n"
		# Add an extra line at the end of the file
		data_string += "\n"
		# Encode data string to utf-8 to make sure it's common encoding
		data_string = data_string.encode('utf-8')
		# Encrypt the data string to be written to file with padding
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		encryptor = AES.new(key, mode, IV=IV)
		config_file_data_in_ciphertext = encryptor.encrypt(data_string + ((16 - len(data_string)%16) * "@"))
		# Write data to file
		encrypted_data_file_output = open(encrypted_path_and_filename, "w+")
		# Write the encrypted data to file
		encrypted_data_file_output.write(config_file_data_in_ciphertext)
		# Close the file
		encrypted_data_file_output.close();
		# Print the message to stdout
		print '[Finished encrypting config file...]'
		# Log to file
		logger.info('[Finished encrypting config file...]')
		# Return success
		return True
	except Exception as e:
		# Collect the exception information
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		# Print the error
		print 'Error writing encrypted config to file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		# Log error with creating checksum map
		logger.error('Error writing encrypted config to file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

# Remove the config file
def remove_config(args_array):
	## Include logger in the main function
	logger = logging.getLogger(args_array["app_name"])
	# Print the success to stdout
	print '[Removing unencrypted config file...]'
	# Log success removing config file
	logger.info('[Removing unencrypted config file...]')
	try:
		# Check that the encrypted version of the file exists already,
		if os.path.isfile(args_array['encrypted_path_and_filename']):
			# Print the success to stdout
			print '[Encrypted config file found...]'
			# Log success removing config file
			logger.info('[Encrypted config file found...]')
			# Check that the unencrypted version of the file exists already,
			if os.path.isfile(args_array['config_path_and_filename']):
				# Delete the file config_path_and_filename
				if args_array['sandbox_mode'] ==  False:
					os.remove(args_array['config_path_and_filename'])
				# Print the success to stdout
				print '[Unencrypted config file removed...]'
				# Log success removing config file
				logger.info('Unencrypted config file removed...')
			else:
				# Print the success to stdout
				print '[Decrypted config file was not found...]'
				# Log success removing config file
				logger.info('Decrypted config file was not found...')
		else:
			# Print the message stdout
			print '[Encrypted config file was not found so config file not deleted...]'
			# Log to file
			logger.info('Encrypted config file was not found so config file not deleted...')
	except Exception as e:
		# Collect the exception information
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		# Print the error
		print 'Error removing unencrypted config file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		# Log error with creating checksum map
		logger.error('Error removing unencrypted config file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

# Confirm encrypted config file exists and can be decrypted using key
def confirm_config(key, encrypted_path_and_filename):
	## Include logger in the main function
	logger = logging.getLogger(args_array["app_name"])
	try:
		# Print message to stdout
		print "[Confirming encrypted config file...]"
		# Log success removing config file
		logger.info("[Confirming encrypted config file...]")
		# Collect the checksum map stored in file to variable called original_filepath_array
		with open(encrypted_path_and_filename) as encrypted_config_file:
			encrypted_config_content = encrypted_config_file.read()
		# Decrypt the file from encrypted format
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		decryptor = AES.new(key, mode, IV=IV)
		encrypted_config_content = decryptor.decrypt(encrypted_config_content)
		# Check that the first line is the password correct confirmation
		# If the password confirmation is not correct, then return false
		if original_file_content[0] == "#":
			# Print message to stdout
			print "[Encrypted file confirmed...]"
			# Log success removing config file
			logger.info("[Encrypted file confirmed...]")
			# Return success message
			return True
		else:
			# Print message to stdout
			print "[Encrypted file did not pass check...]"
			# Log success removing config file
			logger.info("[Encrypted file did not pass check...]")
			return False
	except Exception as e:
		# Collect the exception information
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		# Print the error
		print 'Error checking validity of encrypted config file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		# Log error with creating checksum map
		logger.error('Error checking validity of encrypted config file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

# Build the output for command line instructions
def build_argument_output():
	argument_output = "Usage : apache_config_locker.py [-p <password>] [-open | close | -start | -restart]\n"
	argument_output += "-h, -help : print help menu\n"
	argument_output += "-start : initialize by loading apache with config file and then encrypting it\n"
	argument_output += "-close : just encrypt the config file\n"
	argument_output += "-open : decrypt the config file for editing\n"
	argument_output += "-restart : stop apache, decrypt config file, restart using decrypted config file, and then re-encrypt the config file\n"
	argument_output += "-p <password> : enter the password required to decrypt the data payload\n"
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
	# Set the current working directory
	current_working_directory = os.getcwd() + "/"
	# Base directory of the apache config file
	apache_config_base_directory_path = "/etc/httpd/conf/"
	config_filename = "httpd.conf"
	encrypted_config_path = "/etc/httpd/conf/"
	encrypted_config_filename = "httpd.conf.enc"
	# Build args array to pass to functions
	args_array ={
		# Sandbox mode
		"sandbox_mode" : False,
		# Application Name used in report
		"app_name" : "Apache Config Locker",
		"current_working_directory" : current_working_directory,
		## Declare required variables for filepath and config filename
		"log_filename" : current_working_directory + "log",
		# Build the complete paths and filenames
	    "config_path_and_filename" : apache_config_base_directory_path + config_filename,
	    "encrypted_path_and_filename" : encrypted_config_path + encrypted_config_filename,
		"allowed_args_array" : ["-close", "-restart", "-start", "-open", "-p" "-h", "-help"],
		"apache_script" : "VPS_apachectl.sh"
	}
	## Run function to setup logger
	setup_logger(args_array)
	## Include logger in the main function
	logger = logging.getLogger(args_array["app_name"])
	## Perform analysis of command line args into another array
	args_array["command_args"] = build_command_arguments(sys.argv, args_array)
	## Check return from command line arg bulder and if no command line args
	## print error message and menu
	if args_array["command_args"] == False or args_array["command_args"]["command"] == "h":
		# Print the ASCII header
		print_ascii_header()
		# If the argument failed then print message
		if args_array["command_args"] == False:
			print "\n\nCommand argument failed..."
		## Print out full argument help menu
		build_argument_output()
	## Encrypt the config file and delete unencrypted version
	elif args_array["command_args"]["command"] == "close":
		# Print the ASCII header
		print_ascii_header()
		# Encrypt the config file and remove original
		if encrypt_config(args_array): return_success = remove_config(args_array)
	## Decrypt the config file for editing
	elif args_array["command_args"]["command"] == "open":
		# Print the ASCII header
		print_ascii_header()
		# Decrypt the config file and place into appropriate directory
		decrypt_config(args_array)
	## Start Apache, then encrypt the config file and delete unencrypted version
	elif args_array["command_args"]["command"] == "start":
		# Print the ASCII header
		print_ascii_header()
        # Start apache using the config file
		print "[Starting apache from script...]"
		logger.error("[Starting apache from script...]")
		# Look for the script in payloads directory
		if os.path.isfile("payloads/" + args_array['apache_script']):
			subprocess.call("payloads/" + args_array['apache_script'] + " start", shell=True)
		elif os.path.isfile(args_array['apache_script']):
			subprocess.call("./" + args_array['apache_script'] + " start", shell=True)
		else:
			print "[Could not find the apachectl script...]"
			logger.error("[Could not find the apachectl script...]")
		# Print message that Apache restarted
		print "[Apache restarted from script...]"
		logger.error("[Apache restarted from script...]")
		# Encrypt the config file and remove original
		if encrypt_config(args_array): return_success = remove_config(args_array)
	## Restart Apache and remove the decrypted config file
	elif args_array["command_args"]["command"] == "restart":
		# Print the ASCII header
		print_ascii_header()
		# Start apache using the config file
		print "[Restarting apache from script...]"
		logger.error("[Restarting apache from script...]")
		# Decrypt the config file and place into appropriate directory
		decrypt_config(args_array)
		# Start apache using the config file
		# Look for the script in payloads directory
		if os.path.isfile("payloads/" + args_array['apache_script']):
			subprocess.call("payloads/" + args_array['apache_script'] + " restart", shell=True)
		elif os.path.isfile(args_array['apache_script']):
			subprocess.call("./" + args_array['apache_script'] + " restart", shell=True)
		else:
			print "[Could not find the apachectl script...]"
			logger.error("[Could not find the apachectl script...]")
		# Encrypt the config file and remove original
		if encrypt_config(args_array): return_success = remove_config(args_array)
