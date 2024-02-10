#!/usr/bin/env python3
#
# linearize-hashes.py:  List blocks in a linear, no-fork version of the chain.
#
# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import print_function
try: # Python 3
    import http.client as httplib
except ImportError: # Python 2
    import httplib
import json
import re
import base64
import sys
import os
import os.path

settings = {}

##### Switch endian-ness #####
def hex_switchEndian(s):
	""" Switches the endianness of a hex string (in pairs of hex chars) """
	pairList = [s[i:i+2].encode() for i in range(0, len(s), 2)]
	return b''.join(pairList[::-1]).decode()

class BitcoinRPC:
	def __init__(self, host, port, username, password):
		"""This function initializes an HTTP connection with the provided host, port, username, and password.
		Parameters:
		- host (str): The host to connect to.
		- port (int): The port to connect to.
		- username (str): The username for authentication.
		- password (str): The password for authentication.
		Returns:
		- None: This function does not return any value.
		Processing Logic:
		- Encode the username and password in UTF-8 format.
		- Combine the username and password into a single string.
		- Encode the combined string using base64.
		- Append the encoded string to the "Basic" authentication header.
		- Establish an HTTP connection with the provided host and port, with a timeout of 30 seconds."""
		
		authpair = "%s:%s" % (username, password)
		authpair = authpair.encode('utf-8')
		self.authhdr = b"Basic " + base64.b64encode(authpair)
		self.conn = httplib.HTTPConnection(host, port=port, timeout=30)

	def execute(self, obj):
		"""Executes a JSON-RPC request and returns the response object.
		Parameters:
		- self (type): The current object.
		- obj (type): The JSON-RPC request object.
		Returns:
		- resp_obj (type): The JSON-RPC response object.
		Processing Logic:
		- Sends a POST request with the JSON-RPC request object.
		- Handles ConnectionRefusedError and returns None if connection is refused.
		- Gets the response from the server.
		- Decodes the response body as UTF-8.
		- Loads the response body as a JSON object.
		- Returns the response object."""
		
		try:
			self.conn.request('POST', '/', json.dumps(obj),
				{ 'Authorization' : self.authhdr,
				  'Content-type' : 'application/json' })
		except ConnectionRefusedError:
			print('RPC connection refused. Check RPC settings and the server status.',
			      file=sys.stderr)
			return None

		resp = self.conn.getresponse()
		if resp is None:
			print("JSON-RPC: no response", file=sys.stderr)
			return None

		body = resp.read().decode('utf-8')
		resp_obj = json.loads(body)
		return resp_obj

	@staticmethod
	def build_request(idx, method, params):
		"""Builds a request object for API calls.
		Parameters:
		- idx (int): Index of the request.
		- method (str): Method of the request.
		- params (list): Optional parameters for the request.
		Returns:
		- dict: Request object with version, method, id, and params.
		Processing Logic:
		- Create request object with version, method, and id.
		- If params is None, set params to empty list.
		- Otherwise, set params to given list."""
		
		obj = { 'version' : '1.1',
			'method' : method,
			'id' : idx }
		if params is None:
			obj['params'] = []
		else:
			obj['params'] = params
		return obj

	@staticmethod
	def response_is_error(resp_obj):
		"""Checks if the response object contains an error.
		Parameters:
		- resp_obj (dict): The response object to check for an error.
		Returns:
		- bool: True if the response object contains an error, False otherwise.
		Processing Logic:
		- Check if 'error' key exists.
		- Check if 'error' value is not None."""
		
		return 'error' in resp_obj and resp_obj['error'] is not None

def get_block_hashes(settings, max_blocks_per_call=10000):
	""""Retrieves a list of block hashes from a Bitcoin node using the provided settings and maximum number of blocks per call. Returns a list of block hashes in sequential order."
	Parameters:
	- settings (dict): A dictionary containing the host, port, rpcuser, rpcpassword, min_height, max_height, and rev_hash_bytes settings for connecting to a Bitcoin node.
	- max_blocks_per_call (int): The maximum number of blocks to retrieve per call. Defaults to 10000 if not specified.
	Returns:
	- list: A list of block hashes in sequential order.
	Processing Logic:
	- Connects to a Bitcoin node using the provided settings.
	- Retrieves a batch of block hashes based on the specified maximum number of blocks per call.
	- Checks for any errors in the response and exits the program if necessary.
	- Converts the block hashes to big-endian format if specified in the settings.
	- Prints the block hashes to the console.
	- Continues retrieving block hashes until the maximum height is reached."""
	
	rpc = BitcoinRPC(settings['host'], settings['port'],
			 settings['rpcuser'], settings['rpcpassword'])

	height = settings['min_height']
	while height < settings['max_height']+1:
		num_blocks = min(settings['max_height']+1-height, max_blocks_per_call)
		batch = []
		for x in range(num_blocks):
			batch.append(rpc.build_request(x, 'getblockhash', [height + x]))

		reply = rpc.execute(batch)
		if reply is None:
			print('Cannot continue. Program will halt.')
			return None

		for x,resp_obj in enumerate(reply):
			if rpc.response_is_error(resp_obj):
				print('JSON-RPC: error at height', height+x, ': ', resp_obj['error'], file=sys.stderr)
				exit(1)
			assert(resp_obj['id'] == x) # assume replies are in-sequence
			if settings['rev_hash_bytes'] == 'true':
				resp_obj['result'] = hex_switchEndian(resp_obj['result'])
			print(resp_obj['result'])

		height += num_blocks

def get_rpc_cookie():
	"""Function to retrieve the RPC cookie from a cookie file.
	Parameters:
	- None
	Returns:
	- dict: A dictionary containing the RPC user and password.
	Processing Logic:
	- Open the cookie file.
	- Read the first 5 million characters.
	- Split the string at the colon.
	- Assign the first element to the 'rpcuser' key in the settings dictionary.
	- Assign the second element to the 'rpcpassword' key in the settings dictionary."""
	
	# Open the cookie file
	with open(os.path.join(os.path.expanduser(settings['datadir']), '.cookie'), 'r') as f:
		combined = f.readline(5_000_000)
		combined_split = combined.split(":")
		settings['rpcuser'] = combined_split[0]
		settings['rpcpassword'] = combined_split[1]

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("Usage: linearize-hashes.py CONFIG-FILE")
		sys.exit(1)

	f = open(sys.argv[1])
	for line in f:
		# skip comment lines
		m = re.search('^\s*#', line)
		if m:
			continue

		# parse key=value lines
		m = re.search('^(\w+)\s*=\s*(\S.*)$', line)
		if m is None:
			continue
		settings[m.group(1)] = m.group(2)
	f.close()

	if 'host' not in settings:
		settings['host'] = '127.0.0.1'
	if 'port' not in settings:
		settings['port'] = 8332
	if 'min_height' not in settings:
		settings['min_height'] = 0
	if 'max_height' not in settings:
		settings['max_height'] = 313000
	if 'rev_hash_bytes' not in settings:
		settings['rev_hash_bytes'] = 'false'

	use_userpass = True
	use_datadir = False
	if 'rpcuser' not in settings or 'rpcpassword' not in settings:
		use_userpass = False
	if 'datadir' in settings and not use_userpass:
		use_datadir = True
	if not use_userpass and not use_datadir:
		print("Missing datadir or username and/or password in cfg file", file=stderr)
		sys.exit(1)

	settings['port'] = int(settings['port'])
	settings['min_height'] = int(settings['min_height'])
	settings['max_height'] = int(settings['max_height'])

	# Force hash byte format setting to be lowercase to make comparisons easier.
	settings['rev_hash_bytes'] = settings['rev_hash_bytes'].lower()

	# Get the rpc user and pass from the cookie if the datadir is set
	if use_datadir:
		get_rpc_cookie()

	get_block_hashes(settings)
