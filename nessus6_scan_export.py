import requests
import json
import sys
import time
"""
import requests
import logging

# These two lines enable debugging at httplib level (requests->urllib3->http.client)
# You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
# The only thing missing will be the response.body which is not logged.
try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
http_client.HTTPConnection.debuglevel = 1

# You must initialize logging, otherwise you'll not see debug output.
logging.basicConfig() 
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
"""

url = 'https://nessusscanner.example.com'
verify = False
token = ''
username = 'username'
password = 'password'
history_days = int(7)
export_format = 'pdf'


def build_url(resource):
	return '{0}{1}'.format(url, resource)


def connect(method, resource, data=None):
	"""
	Send a request

	Send a request to Nessus based on the specified data. If the session token
	is available add it to the request. Specify the content type as JSON and
	convert the data to JSON format.
	"""
	headers = {'X-Cookie': 'token={0}'.format(token),
			   'content-type': 'application/json'}

	data = json.dumps(data)

	if method == 'POST':
		r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
	elif method == 'PUT':
		r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
	elif method == 'DELETE':
		r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
	else:
		r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)

	# Exit if there is an error.
	if r.status_code != 200:
		e = r.json()
		print e['error']
		sys.exit()

	# When downloading a scan we need the raw contents not the JSON data. 
	if 'download' in resource:
		return r.content
	elif ('DELETE' == method and '/session' in resource):
		return r.content
	else:
		return r.json()


def login(usr, pwd):
	"""
	Login to nessus.
	"""
	login = {'username': usr, 'password': pwd}
	data = connect('POST', '/session', data=login)

	return data['token']


def logout():
	"""
	Logout of nessus.
	"""
	connect('DELETE', '/session')


def get_recent_scans():
	"""
	Get scans completed in last X days
	Create a dictionary of scan uuids to be used for requesting export
	"""
	epoch_day=int(86400)
	last_mod = int(time.time() - (epoch_day * history_days))
	data = connect('GET', '/scans?last_modification_date={0}'.format(last_mod))
	
	return data

	
def export_status(sid, fid):
	"""
	Check export status
	Check to see if the export is ready for download.
	"""
	data = connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid))

	return data['status'] == 'ready'


def export(sid):
	"""
	Make an export request
	Request an export of the scan results for the specified scan and
	historical run. In this case the format is hard coded as nessus but the
	format can be any one of nessus, html, pdf, csv, or db. Once the request
	is made, we have to wait for the export to be ready.
	"""
	if export_format == "html":
		print ("Export HTML format")
		data = {'format': export_format, 'chapters':'vuln_hosts_summary; vuln_by_host; compliance_exec; remediations; vuln_by_plugin; compliance'}
	else:
		print ("Export nessus format")
		data = {'format': export_format}

	data = connect('POST', '/scans/{0}/export'.format(sid), data=data)

	fid = data['file']

	while export_status(sid, fid) is False:
		time.sleep(5)

	return fid


def download(sid, fid, name):
	"""
	Download the scan results
	Download the scan results stored in the export file specified by fid for
	the scan specified by sid.
	"""
	data = connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid))
	valid_chars='-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
	safename = ''.join(c for c in name if c in valid_chars)
	filename = 'nessus_{0}_{1}_{2}.{3}'.format(safename,sid, fid, export_format)

	print('Saving scan results to {0}.'.format(filename))
	with open(filename, 'w') as f:
		f.write(data)


if __name__ == '__main__':
	print("Login")
	token = login(username, password)

	print("Fetching list of recently completed scans")
	recentscans = get_recent_scans()
	
	
	for k in recentscans["scans"]:
		if(k['status'] == "completed"):
			print("Exporting " + k['name'])
			file_id = export(k['id'])
			print("Download exported scan")
			download(k['id'], file_id, k['name'])
		else:
			print("Skipping unfinished scan " + k['name'])

	print('Logout')
	logout()
