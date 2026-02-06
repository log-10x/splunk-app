import argparse
import ssl
import logging

import tenx_util
import tenx_consts
import tenx_search_manager
import tenx_search_builder

logging.getLogger().addHandler(logging.StreamHandler())
logging.getLogger().setLevel(logging.INFO)


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--host', type=str, required=True, help="Splunk host name")
	parser.add_argument('--user', type=str, required=True, help="Splunk Username")
	parser.add_argument('--key', type=str, required=True, help="Splunk API key")
	parser.add_argument('--search', type=str, required=False, help="Search string to translate to 10x compatible")

	args = parser.parse_args()

	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE

	server_connection = tenx_util.ServerConnection(
		args.host,
		args.user,
		{"bearer_token": args.key},
		ctx)

	search_manager = tenx_search_manager.TenxSearchManager(server_connection, tenx_consts.DEFAULT_CONFIG)
	search_builder = tenx_search_builder.TenxSearchBuilder(server_connection, tenx_consts.DEFAULT_CONFIG, search_manager, True)

	resolved = search_builder.resolve(args.search)

	print("Base search -\n\t%s\nTenx search -\n\t%s" % (args.search, resolved))


if __name__ == '__main__':
	main()
