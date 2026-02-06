import sys
import argparse
import json
import csv

import tenx_consts
import tenx_dml_builder


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--input', type=str, required=True, help="10x pattern file in json format")
	parser.add_argument('--ocsv', type=str, required=False, help="CSV formatted output, for lookup table")
	parser.add_argument('--odml', type=str, required=False, help="Pure dml file output, for dml search")
	parser.add_argument('--cloud', required=False, action='store_true', help="Exports the data in a format compatible with cloud demo")

	args = parser.parse_args()

	if not args.ocsv and not args.odml:
		print("No outputs specified, please specify either --ocsv or --odml (or both)")
		sys.exit(1)

	csv_record_key = "_KEY"

	try:
		with open(args.input, 'r') as input_file:
			csv_writer = None
			output_dml = None

			if args.ocsv:
				csv_writer = csv.writer(open(args.ocsv, 'w', newline=''))
				headers = [csv_record_key] + tenx_dml_builder.RECORD_HEADERS

				csv_writer.writerow(headers)

			if args.odml:
				output_dml = open(args.odml, 'w')

			dml_builder = tenx_dml_builder.TenxDMLBuilder(
				timestamp_placeholder=tenx_consts.DEFAULT_CONFIG['timestamp_placeholder'],
				variable_separator=tenx_consts.DEFAULT_CONFIG['variable_separator'])

			for line in input_file.readlines():
				processed = json.loads(line)

				if 'templateHash' not in processed or 'template' not in processed:
					print('Missing templateHash/template in line:')
					print(line)
					sys.exit(2)

				template_hash = processed['templateHash']
				template = processed['template']

				if csv_writer:
					record = dml_builder.build_kv_record_data(template_hash, template)

					if args.cloud:
						record[tenx_dml_builder.RECORD_PATTERN_PARTS] = "@@".join(record[tenx_dml_builder.RECORD_PATTERN_PARTS])

					values = [template_hash] + [record[key] for key in tenx_dml_builder.RECORD_HEADERS]

					csv_writer.writerow(values)

				if output_dml:
					event = dml_builder.build_pure_dml_line(template_hash, template)
					output_dml.write(event + '\n')

	except FileNotFoundError:
		print("Input file {} not found.".format(args.input))


if __name__ == '__main__':
	main()
