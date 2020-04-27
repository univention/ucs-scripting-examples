#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
#
# Copyright 2020 Univention GmbH
#
# http://www.univention.de/
#
# All rights reserved.
#
# The source code of this program is made available
# under the terms of the GNU Affero General Public License version 3
# (GNU AGPL V3) as published by the Free Software Foundation.
#
# Binary versions of this program provided by Univention to you as
# well as other copyrighted, protected or trademarked materials like
# Logos, graphics, fonts, specific documentations and configurations,
# cryptographic keys etc. are subject to a license agreement between
# you and Univention and not subject to the GNU AGPL V3.
#
# In the case you use this program under the terms of the GNU AGPL V3,
# the program is provided in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License with the Debian GNU/Linux or Univention distribution in file
# /usr/share/common-licenses/AGPL-3; if not, see
# <http://www.gnu.org/licenses/>.

"""
	Example script for migration of user from an external LDAP
	to Univention Directory Manager
	via python-univention-directory-manager
"""

import ldif
import ldap
from multiprocessing import Process, Queue
import os
import univention.admin.modules as udm_modules
from univention.admin.uexceptions import uidAlreadyUsed, valueInvalidSyntax
from univention.lib.misc import createMachinePassword
from univention.management.console.ldap import get_admin_connection
import univention.uldap  # low level wrapper class around a python-ldap connection
import sys


def create_udm_user_from_ldap_attrs(ldap_object_dn, ldap_object_attrs, access_to_local_ldap, pos, udm_users):
	""" Example for creation of a UDM users/user object
		where the required UDM properties are derived from the given LDAP attributes.

		TODO:
			* project specific translation rules from source LDAP atributes to UDM properties
			* position of object creation
			* stuff like group memberships

		FYI: A bit of terminology:
			* UDM "properties" are "mapped" to LDAP attributes
			* usually they have a 1:1 relation to LDAP attributes,
			  but sometimes they are also more abstract, like "disabled" or "pwdChangeNextLogin"
	"""
	print('Processing {}'.format(ldap_object_dn))
	user = udm_users.object(None, access_to_local_ldap, pos)
	user.open()

	try:
		uid = ldap_object_attrs['uid'][0]
	except KeyError:
		print('ERROR: Missing "uid" attribute, skipping record {}'.format(ldap_object_dn))
		return
	try:
		sn = ldap_object_attrs['sn'][0]
	except KeyError:
		print('ERROR: Missing "sn" attribute, skipping record {}'.format(ldap_object_dn))
		return
	try:
		user['username'] = uid  # username is a required "property" of the UDM users/user object
	except valueInvalidSyntax as ex:
		print('Invalid username: {} in object {}: {}'.format(uid, ldap_object_dn, ex.args[0]))
		return

	user['lastname'] = sn   # lastname is a required "property" of the UDM users/user object
	user['password'] = createMachinePassword()	# likewise, e.g. initialize with a random password
	user['disabled'] = "1"  # e.g. create it as disabled.

	try:
		user.create()
		print('Created {}'.format(uid))
	except uidAlreadyUsed:
		print('Skipping {}, aleady exists.'.format(uid))
		return


### Below an simple example idea for efficient processing:
# * Read objects from remote LDAP with paged searches
# * Stuff them into a queue
# * Run a number of sub-processes to scale CPU bound UDM object construction
#
# Here are the example knobs for scaling:

LDAP_OBJECTS_PAGE_SIZE = 1000
LDAP_OBJECTS_QUEUE_SIZE = 5000
UDM_WRITERS = 4


def ldap_object_consumer(queue, id, access_to_local_ldap, pos, udm_users):
	""" consumer, pulling objects out of the queue
		and running create_udm_user_from_ldap_attrs on each.

		Should probably be turned into a class method
		together with create_udm_user_from_ldap_attrs to
		avoid passing a bunch of arguments.
	"""
	print('Starting UDM Writer {}'.format(id))
	while True:
		res = queue.get()
		if res is None:
			# the producer emited None to indicate that it is done
			# indicate this to the other workers too
			queue.put(None)
			break

		ldap_object_dn, ldap_object_attrs = res
		create_udm_user_from_ldap_attrs(ldap_object_dn, ldap_object_attrs, access_to_local_ldap, pos, udm_users)


def paged_remote_ldap_object_reader(queue, access_to_source_ldap, processed_entryuuids):
	""" producer, retrieving objects from a remote LDAP
		in batch sizes of LDAP_OBJECTS_PAGE_SIZE and appending them to a work queue.
	"""
	print('Starting LDAP Reader')

	page_control = ldap.controls.SimplePagedResultsControl(True, size=LDAP_OBJECTS_PAGE_SIZE, cookie='')
	response = access_to_source_ldap.lo.search_ext(
		access_to_source_ldap.base,
		ldap.SCOPE_SUBTREE,
		'objectClass=posixAccount', ['*', 'entryUUID'],
		serverctrls=[page_control]
	)

	while True:
		rtype, rdata, rmsgid, serverctrls = access_to_source_ldap.lo.result3(response)

		# put all objects of the result data into the queue
		for res in rdata:
			entryUUID = res[1]['entryUUID'][0]
			if entryUUID not in processed_entryuuids:
				queue.put(res)
				processed_entryuuids.append(entryUUID)

		controls = [
			control for control in serverctrls
			if control.controlType == ldap.controls.SimplePagedResultsControl.controlType
		]
		if not controls:
			print('The server ignores RFC 2696 control')
			break
		if not controls[0].cookie:
			break
		page_control.cookie = controls[0].cookie
		response = access_to_source_ldap.lo.search_ext(
			access_to_source_ldap.base,
			ldap.SCOPE_SUBTREE,
			'objectClass=posixAccount', ['*', 'entryUUID'],
			serverctrls=[page_control]
		)
	# signal end of queue
	queue.put(None)


def reconnect_paged_remote_ldap_object_reader(queue, access_to_source_ldap):
	processed_entryuuids = []  # keep track of processes entries in case of remote connection timeouts
	while True:
		try:
			paged_remote_ldap_object_reader(queue, access_to_source_ldap, processed_entryuuids)
		except (ldap.SERVER_DOWN, ldap.UNAVAILABLE, ldap.CONNECT_ERROR, ldap.TIMEOUT):
			lo = access_to_source_ldap.lo
			lo.reconnect(lo._uri, retry_max=lo._retry_max, retry_delay=lo._retry_delay)
			continue
		else:
			break


class LdifObjectReader(ldif.LDIFParser):
	def __init__(self, queue, input):
		ldif.LDIFParser.__init__(self, input)
		self.queue = queue

	def handle(self, dn, entry):
		self.queue.put((dn, entry))


def ldif_file_object_reader(queue, filename):
	""" producer, reading LDAP objects from an ldif file
		and appending them to a work queue.
	"""
	print('Starting LDIF Reader')

	with open(filename) as f:
		lf = LdifObjectReader(queue, f)
		try:
			lf.parse()
		except ValueError as ex:
			print("LDIF parsing error: %s" % (ex.args[0]))

	# signal end of queue
	queue.put(None)


def main():
	### Step 1) Open connection to remote (source) LDAP server
	#
	# TODO: Replace example strings below
	#
	remote_ldap_base = 'dc=remote,dc=domain,dc=net'
	remote_ldap_binddn = 'uid=Administrator,cn=users,%s' % remote_ldap_base
	remote_ldap_bindpw = 'Fill in the password'
	remote_ldap_uri = 'ldaps://server.remote.domain.net:636'
	# remote_ldap_start_tls = 2  # this means force TLS in uldap.access
	remote_ldap_start_tls = 0
	remote_ldap_ca_certfile = '/var/tmp/remote_ldap_ca_certfile.pem'

	## Alternative: read from an LDIF file
	#  remote_ldap_uri = 'file:///var/tmp/users.ldif'

	if remote_ldap_uri.startswith('ldap'):
		## E.g. use "low level" univention.uldap class (wrapper around python-ldap)
		#
		access_to_source_ldap = univention.uldap.access(
			uri=remote_ldap_uri,
			base=remote_ldap_base,
			binddn=remote_ldap_binddn,
			bindpw=remote_ldap_bindpw,
			start_tls=remote_ldap_start_tls,
			ca_certfile=remote_ldap_ca_certfile
		)

		## Alternative: use plain python-ldap directly
		#
		# source_ldap = ldap.initialize('ldaps://%s:%s' % (remote_ldap_host, remote_ldap_port))
		# source_ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, remote_ldap_ca_certfile)
		# source_ldap.simple_bind_s(remote_ldap_binddn, remote_ldap_bindpw)
		# source_ldap.set_option(ldap.OPT_REFERRALS, 0)

	elif remote_ldap_uri.startswith('file://'):
		if not os.path.exists(remote_ldap_uri[7:]):
			print("File {} does not exist".format(remote_ldap_uri[7:]))
			sys.exit(1)
	else:
		print("LDAP URI must start either with 'file://', 'ldap://' or 'ldaps://'")
		sys.exit(1)

	### Step 2) Get a connection to the local LDAP server with admin credentials
	access_to_local_ldap, pos = get_admin_connection()
	pos.setDn('cn=users')

	### Initialize the UDM module users/user, to create user objects
	udm_modules.update()  # required to load all modules and extended attributes
	udm_users = udm_modules.get('users/user')

	### Create queue and start UDM writers as subprocesses
	queue = Queue(LDAP_OBJECTS_QUEUE_SIZE)
	udm_workers = list()
	for i in range(UDM_WRITERS):
		p = Process(target=ldap_object_consumer, args=(queue, i, access_to_local_ldap, pos, udm_users))
		p.start()
		udm_workers.append(p)

	print("Ok, here we go, starting import")
	if remote_ldap_uri.startswith('file://'):
		ldif_file_object_reader(queue, remote_ldap_uri[7:])
	else:
		reconnect_paged_remote_ldap_object_reader(queue, access_to_source_ldap)
	print("All data read, waiting for workers to finish")
	for p in udm_workers:
		p.join()


if __name__ == '__main__':
	main()

# vim: set ft=python ts=4 sw=4 noet :
