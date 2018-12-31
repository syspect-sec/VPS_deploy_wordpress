#!/usr/bin/env python
# Apache Config Locker
# Description--
# Decripts payload, randomizes order of entries to text file, and removes payload.
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
## Take the cleartext password file and output encrypted payload
def output_payload(args_array):
	try:
		# Collect the checksum map stored in file to variable called original_filepath_array
		with open(args_array['payload_in_filename'], "r") as payload_in_file:
			payload_content = payload_in_file.read()
		print len(payload_content)
		# Decrypt the file from encrypted format
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		decryptor = AES.new(args_array['command_args']['key'], mode, IV=IV)
		payload_content = decryptor.decrypt(payload_content)
		# Check that the first line is the password correct confirmation
		# If the password confirmation is not correct, then return false
		if payload_content[0] != "#":
			print "dino say me no like passghetti..."
			return False
		else:
			print "dinner in dinner out... dino looking for toilet..."
			# Make an array to put passphrasess into
			payload_content_array = payload_content.splitlines()
			payload_content_filtered = []
			print payload_content_array
			# You may also want to remove whitespace characters like `\n` at the end of each line
			for line in payload_content:
				# Ignore character used to pad the encryption
				if "@" not in line and "#" not in line:
					# Append the passphrase to array
					payload_content_filtered.append(line)
			# Randomize the array before writing to file
			random.shuffle(payload_content_filtered)
			if args_array['sandbox_mode'] == False:
				# Write the payload content into original encrypted file
				payload_out_filename = open(args_array['payload_out_filename'], "w")
				for line in payload_content_array:
					payload_out_filename.write(line)
				payload_out_filename.close()
			else:
				# Write the payload content into original passphrase_gen file
				payload_out_filename = open(args_array['payload_out_filename_sandbox'], "w")
				for line in payload_content_array:
					payload_out_filename.write(line)
				payload_out_filename.close()
			# Print success message
			print "dino says look what I made..."
	except Exception as e:
		# Collect the exception information
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		# Print the error
		print 'Failed to build command arguments: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		# Log error with creating filepath
		logger.error('Failed to build command arguments: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False
## Parses the command argument sys.arg into command set, also encrypt password for use
def build_command_arguments(args, args_array):
	## Include logger in the main function
	logger = logging.getLogger(args_array['app_name'])
	try:
		# Create an array to store modified command line arguemnts
		command_args = {}
		# Pop off the first element of array because it's the application filename
		args.pop(0)
		if "-in" in args or "-out" in args:
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
				# Append the key back onto the end of the command line arguement array
				command_args.update({"key" : key})
			# If there is no password argument, then the command line is failed
			elif "-p" not in args:
				print "password please..."
				return False
			if len(args) != 1:
				print "too many args... (arg!) ..."
				return False
		# For loop to modify elements and strip "-"
		for item in args:
			if item in args_array['allowed_args_array']:
				item = item.replace('-', '')
				command_args.update({"command" : item})
			else:
				print "bad args... (arg!)..."
				return False
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
# Encrypt the configuration file
def input_payload(args_array):
	# Use the config_path_and_filename to find the file and store in enncrypted_path_and_filename
	try:
		# Open the file and encrypt
		payload_in_filename = open(args_array['passphrase_gen_filename'], "r")
		file_array = payload_in_filename.readlines()
		# Create a string to write to file
		data_string = "#\n"
		for item in file_array:
			data_string += item
		# Encode data string to utf-8 to make sure it's common encoding
		data_string = data_string.encode('utf-8')
		# Encrypt the data string to be written to file with padding
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		encryptor = AES.new(args_array['command_args']['key'], mode, IV=IV)
		file_data_in_ciphertext = encryptor.encrypt(data_string + ((16 - len(data_string)%16) * "@"))
		# Write data to file
		payload_out_filename = open(args_array['payload_out_filename'], "w")
		# Write the encrypted data to file
		payload_out_filename.write(file_data_in_ciphertext)
		# Close the file
		payload_out_filename.close();
	except Exception as e:
		# Collect the exception information
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		# Print the error
		print 'Error writing encrypted payload file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		# Log error with creating checksum map
		logger.error('Error writing encrypted payload to file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False
# Used to generate a passphrase file
def generate_passwords_file(args_array):
	# Open passphrase file to write
	passphrase_file = open(args_array['passphrase_gen_filename'], "w")
	# Generate list of possible passphrases and write to file
	for item in range(10000):
		passphrase = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for char in range(100))
		print(passphrase)
		passphrase_file.write(passphrase + "\n")
	passphrase_file.close()
	print "Passphrase file created..."
# Setup logging
def setup_logger(args_array):
    logger = logging.getLogger(args_array['app_name'])
    log_handler = logging.FileHandler(args_array['log_filename'])
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)
## Main Function Starts Here ##
if __name__ == '__main__':
	## Declare required variables for filepath and config filename
	args_array = {
		"sandbox_mode" : False,
		"cwd" : os.getcwd(),
		"payload_in_filename" : cwd + "required_files/random_passwords",
		"payload_out_filename" : cwd + "payloads/random_passwords",
		"payload_out_filename_sandbox" : : cwd + "payloads/random_passwords_sandbox",
		"passphrase_gen_filename" : "required_files/passwords",
		"log_filename" : "log",
		"app_name" : "Passphrase Payload",
		"allowed_args_array" : ["-in", "-out", "-p", "-gen"]
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
		print "command line fail captain!!"
	## If command line set to generate a list of passphrases
	elif args_array['command_args']['command'] == "gen":
		generate_passwords_file(args_array)
	## If command line set to encrypt a payload
	elif args_array['command_args']['command'] == "in":
		print "Let me mock your dinnersaurus rex sir..."
		input_payload(args_array)
	## If command line set to decrypt a payload
	elif args_array['command_args']['command'] == "out":
		output_payload(args_array)
	print "Dung like dinnersaurus!"
