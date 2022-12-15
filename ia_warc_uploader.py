#!/usr/bin/python3

# A modified version of ArchiveBot's uploader, which is:		
#		
# Copyright (c) 2013 David Yip		
# 		
# Permission is hereby granted, free of charge, to any person obtaining a copy		
# of this software and associated documentation files (the "Software"), to deal		
# in the Software without restriction, including without limitation the rights		
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell		
# copies of the Software, and to permit persons to whom the Software is		
# furnished to do so, subject to the following conditions:		
# 		
# The above copyright notice and this permission notice shall be included in		
# all copies or substantial portions of the Software.		
# 		
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR		
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,		
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE		
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER		
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,		
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN		
# THE SOFTWARE.

"""
uploader.py: upload WARC files toward the Internet Archive
rsync mode (RSYNC_URL set): upload everything to an rsync endpoint
such as fos.
s3 mode (S3_URL set): upload everything directly to the Internet Archive
"""

from __future__ import print_function

import os
import time
import subprocess
import sys
import re
import datetime
import json
import hashlib
import requests
import json

class Params:
	"""
	Encapsulation of global parameters from environment and derivation
	"""
	def __init__(self):
		if len(sys.argv) > 1:
			self.directory = sys.argv[1]
		elif os.environ.get("FINISHED_WARCS_DIR") != None:
			self.directory = os.environ["FINISHED_WARCS_DIR"]
		else:
			raise RuntimeError(
				"No directory specified (set FINISHED_WARCS_DIR "
				"or specify directory on command line)")

		self.url = os.environ.get("RSYNC_URL")
		if self.url != None:
			if "/localhost" in self.url or "/127." in self.url:
				raise RuntimeError(
					"Won't let you upload to localhost because I "
					"remove files after uploading them, and you "
					"might be uploading to the same directory")
			self.mode = "rsync"

		self.successful_uploads_file = os.environ.get("SUCCESSFUL_UPLOADS_FILE")
		if self.successful_uploads_file is None:
			raise RuntimeError("Must specify SUCCESSFUL_UPLOADS_FILE")

		self.item_part_count_file = os.environ.get("ITEM_PART_COUNT_FILE")
		if self.item_part_count_file is None:
			raise RuntimeError("Must specify ITEM_PART_COUNT_FILE")

		if self.url is None:
			self.url = os.environ.get("S3_URL")
			if self.url is not None:
				self.mode = "s3"

		if self.url is None:
			raise RuntimeError(
				"Neither RSYNC_URL nor S3_URL are set - nowhere to upload to.  "
				"Hint: use S3_URL=https://s3.us.archive.org")

		if self.mode == "s3": # Parse IA-S3-specific options
			self.ia_collection = os.environ.get("IA_COLLECTION")
			#if self.ia_collection is None:
			#	raise RuntimeError("Must specify IA_COLLECTION if using IA S3")

			self.ia_item_title = os.environ.get("IA_ITEM_TITLE")
			if self.ia_item_title is None:
				raise RuntimeError("Must specify IA_ITEM_TITLE if using IA S3")

			self.ia_auth = os.environ.get("IA_AUTH")
			if self.ia_auth is None:
				raise RuntimeError("Must specify IA_AUTH if using IA S3 (hint: access_key:secret_key)")

			self.ia_item_prefix = os.environ.get("IA_ITEM_PREFIX")
			if self.ia_auth is None:
				raise RuntimeError("Must specify IA_ITEM_PREFIX if using IA S3")

			self.ia_access = os.environ.get("IA_ACCESS")
			if self.ia_access is None:
				raise RuntimeError("Must specify IA_ACCESS if using IA S3 (hint: your access key)")

		self.wait = int(os.environ.get("WAIT", 60))

def try_mkdir(path):
	try:
		os.mkdir(path)
	except OSError:
		pass

def should_upload(basename):
	assert not "/" in basename, basename
	return not basename.startswith(".") and basename.endswith(".warc.gz")

def parse_name(basename):
	# e.g. www.reddit.com-r-subreddit-2017-04-26-acc19c9e-00000.warc.gz
	# e.g. www.reddit.com-r-subreddit-2017-04-26-acc19c9e-meta.warc.gz
	k = re.split(r"(.*)-(\d{4})-(\d{2})-(\d{2})-........-(meta|\d{5})\.warc\.gz", basename)
	try:
		dns = k[1]
	except IndexError:
		# WARCs created by an early version of grab-site lack the random identifier
		k = re.split(r"(.*)-(\d{4})-(\d{2})-(\d{2})-(meta|\d{5})\.warc\.gz", basename)
		dns = k[1]
	return {"dns": dns, "date": "%s%s%s" % (k[2], k[3], k[4])}

def ia_upload_allowed(s3_url, accesskey, bucket=""):
	try:
		quota_url = "{}/?check_limit=1&accesskey={}&bucket={}".format(s3_url, accesskey, bucket)
		resp = requests.get(url=quota_url)
		data = json.loads(resp.text)
	except (requests.RequestException, json.JSONDecodeError) as err:
		print("Could not get throttling status - assuming IA is down")
		print("Exception: {}".format(err))
		return False

	if "over_limit" in data and data["over_limit"] is not 0:
		print("IA S3 API notifies us we are being throttled (over_limit)")
		return False

	if "detail" in data and "rationing_engaged" in data["detail"] and data["detail"]["rationing_engaged"] is not 0:
		quota_our_remaining    = data["detail"]["accesskey_ration"]   - data["detail"]["accesskey_tasks_queued"]
		quota_global_remaining = data["detail"]["total_global_limit"] - data["detail"]["total_tasks_queued"]
		quota_bucket_remaining = data["detail"]["bucket_ration"]      - data["detail"]["bucket_tasks_queued"]

		if quota_our_remaining < 10 or quota_global_remaining < 10 or quota_bucket_remaining < 5:
			print("IA S3 API notifies us rationing is engaged with little room for new work!")
			print("Our outstanding jobs:   {}".format(data["detail"]["accesskey_tasks_queued"]))
			print("Our remaining quota:    {}".format(quota_our_remaining))
			print("Global remaining quota: {}".format(quota_global_remaining))
			print("Limit reason given: {}".format(data["detail"]["limit_reason"]))
			return False
		else:
			print("IA S3 API notifies us rationing is engaged but we have room for another job.")

	return True

def file_md5(fname):
	md5 = hashlib.md5()
	with open(fname, "rb") as inputfile:
		while True:
			block = inputfile.read(2**16)
			if not block:
				break
			md5.update(block)

	return md5.hexdigest()

def shortened(name):
	if len(name) <= 80:
		return name
	else:
		return name[:39] + "_" + name[-40:]

def ia_s3_ship(fname, basename, item, params: Params, part=1):
	bucket_unescaped_name = params.ia_item_prefix + "_" + shortened(item["dns"]) + "_" + item["date"]
	ia_upload_bucket      = re.sub(r"[^0-9a-zA-Z-]+", "_", bucket_unescaped_name)
	item_title            = params.ia_item_title + " " + item["dns"] + " " + item["date"]
	if part > 1:
		ia_upload_bucket += "_part_%d" % (part,)
		item_title       += " part %d" % (part,)

	if not ia_upload_allowed(params.url, params.ia_access, ia_upload_bucket):
		# IA is throttling
		# At some point, an ambitious person could try a file belonging
		# in a different bucket if ia_upload_allowed denied this one
		return 1

	size_hint = str(os.stat(fname).st_size)
	compat_filename = shortened(re.sub(r"[^0-9a-zA-Z-.]+", "_", basename))
	if compat_filename is "" or compat_filename[0] is "_":
		# IA filenames cannot be empty or start with underscore
		compat_filename = "z" + compat_filename[1:]

	target = params.url + "/" + ia_upload_bucket + "/" + compat_filename
	md5sum = file_md5(fname)
	args   = [
		"curl",
		"-v",
		"--location",
		"--fail",
		"--speed-limit", "1",
		"--speed-time", "900",
		"--header", "Content-MD5: " + md5sum,
		"--header", "x-archive-queue-derive:1",
		"--header", "x-amz-auto-make-bucket:1",
		#"--header", "x-archive-meta-collection:" + params.ia_collection,
		"--header", "x-archive-meta-mediatype:web",
		"--header", "x-archive-meta-subject:warcarchives",
		"--header", "x-archive-meta-title:" + item_title,
		"--header", "x-archive-meta-date:" + item["date"][0:4] + "-" + item["date"][4:6] + "-" + item["date"][6:8],
		"--header", "x-archive-size-hint:" + size_hint,
		"--header", "authorization: LOW " + params.ia_auth,
		"-o", "/dev/stdout",
		"--upload-file", fname,
		target]
	#print(repr(args))
	return subprocess.call(args)


def write_json(filename, obj):
	with open(filename, "w") as f:
		f.write(json.dumps(obj))


def item_string_key(item):
	return item["dns"] + "_" + item["date"]


def main():
	params = Params()

	print("CHECK THE UPLOAD TARGET: %s as %s endpoint" % (params.url, params.mode))
	print()
	print("Upload target must reliably store data")
	print("Each local file will removed after upload")
	print("Hit CTRL-C immediately if upload target is incorrect")
	print()

	uploading_dir = os.path.join(params.directory, "_uploading")
	try_mkdir(uploading_dir)

	try:
		item_part_count = json.loads(open(params.item_part_count_file, "r").read())
	except FileNotFoundError:
		print("Notice: ITEM_PART_COUNT_FILE does not exist; will create one")
		item_part_count = {}

	need_wait = True
	while True:
		if need_wait:
			print("Waiting {} seconds".format(params.wait))
			time.sleep(params.wait)

		need_wait = True

		fnames = sorted(list(f for f in os.listdir(params.directory) if should_upload(f)))
		if len(fnames):
			basename = fnames[0]
			fname_d = os.path.join(params.directory, basename)
			fname_u = os.path.join(uploading_dir, basename)
			if os.path.exists(fname_u):
				print("%r already exists - another uploader probably grabbed it" % (fname_u,))
				continue
			try:
				os.rename(fname_d, fname_u)
			except OSError:
				print("Could not rename %r - another uploader probably grabbed it" % (fname_d,))
			else:
				print("Uploading %r" % (fname_u,))

				item = parse_name(basename)
				print(repr(item))

				if params.mode == "rsync":
					exit_code = subprocess.call([
						"rsync", "-av", "--timeout=300", "--contimeout=300",
						"--progress", fname_u, params.url])
				elif params.mode == "s3":
					part      = item_part_count.get(item_string_key(item), 1)
					exit_code = ia_s3_ship(fname_u, basename, item, params, part=part)
					# exit code 22 from curl most likely indicates that we got a
					# 403 from archive.org, which most likely happened because
					# the disk was full on the machine hosting an item.
					if exit_code == 22:
						exit_code = ia_s3_ship(fname_u, basename, item, params, part=part + 1)
						# Do this only _after_ we make a successful upload to avoid creating things
						# like "part 2" "part 4" with no part 3
						if exit_code == 0:
							item_part_count[item_string_key(item)] = part + 1
							write_json(params.item_part_count_file, item_part_count)
				else:
					# No upload mechanism available
					exit_code = 1

				if exit_code == 0:
					print("Removing %r" % (fname_u,))
					os.remove(fname_u)
					with open(params.successful_uploads_file, "ab") as f:
						f.write(basename.encode("utf-8") + b"\n")
					need_wait = False
				else:
					# Move it out of the _uploading directory so that this
					# uploader (or another one) can try again.
					os.rename(fname_u, fname_d)
		else:
			print("Nothing to upload")


if __name__ == "__main__":
	main()
