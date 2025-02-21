#!/usr/bin/env python3

import base64
import requests
import os

_headers = {"Referer": 'https://rentry.co'}


class RentryClient:
	"""Simple HTTP Session Client, keeps cookies."""
	
	def __init__(self):
		self.session = requests.Session()
		
	def get(self, url, headers={}):
		response = self.session.get(url, headers=headers)
		response.status_code = response.status_code
		response.data = response.text
		return response
	
	def post(self, url, data=None, headers={}):
		response = self.session.post(url, data=data, headers=headers)
		response.status_code = response.status_code
		response.data = response.text
		return response

class RentryKeyChain:
	def __init__(self):
		self.new()
		
	def new(self):
		self.key = base64.b64encode(os.urandom(5096))
	
	def get(self):
		return self.key
	
	def load(self, filename):
		with open(filename, 'rb') as file:
			self.key = base64.b64encode(file.read()).decode()
	
	def save(self, filename):
		with open(filename, 'wb+') as file:
			file.write(base64.b64encode(self.key.encode()))

class Rentry:
	def __init__(self, keychain):
		self.keychain = keychain
		self.client = RentryClient()
	
	def get(self, name):
		return self.client.get('https://rentry.co/api/raw/{}'.format(name)).json()
	
	def new(self, name, contents):
		response = client.get('https://rentry.co')
		csrftoken = response.cookies['csrftoken']
		
		payload = {
			'csrfmiddlewaretoken': csrftoken,
			'url': name,
			'edit_code': self.keychain.get(),
			'text': contents
		}
		
		return self.client.post('https://rentry.co/api/new', data=payload, headers=_headers).json()
	
	def edit(self, name, contents):
		response = self.client.get('https://rentry.co')
		csrftoken = response.cookies['csrftoken']
		
		payload = {
			'csrfmiddlewaretoken': csrftoken,
			'edit_code': self.keychain.get(),
			'text': contents
		}
		
		return self.client.post('https://rentry.co/api/edit/{}'.format(name), data=payload, headers=_headers).json()
	
	def __getitem__(self, name):
		return self.get(name)
	
	def __setitem__(self, name, contents):
		try:
			return self.edit(name, contents)
		except:
			return self.new(name, contents)

	
	
