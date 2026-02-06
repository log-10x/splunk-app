"""
Tenx Constants Module
====================

This module defines default configuration values and constants used throughout
the tenx-for-splunk Splunk app. These defaults are used when tenx_config.conf settings
are missing or cannot be loaded.

Configuration Hierarchy
-----------------------
1. tenx_config.conf settings (highest priority)
2. DEFAULT_CONFIG values (fallback)

Constants
---------
TENX_EXTRACTION_NAME : str
    The props.conf key name that references the field extraction transform.
    Default: 'REPORT-tenx'

TENX_EXTRACTION : str
    The transforms.conf stanza name for 10x field extraction.
    Default: 'tenx-hash-vars-extraction'

DEFAULT_CONFIG : dict
    Default values for all configurable settings:

    - dest_dml_index: Index for processed template events (default: 'main')
    - dml_source_type: Sourcetype for processed templates (default: 'tenx_dml_pure')
    - collection_name: KV store collection name (default: 'kvdml')
    - timestamp_placeholder: Placeholder text for timestamps (default: '__TENX_TS__')
    - variable_separator: Character separating variables in templates (default: '$')
    - tenx_extraction_name: props.conf key for extraction (default: 'REPORT-tenx')
    - tenx_extraction: transforms.conf stanza name (default: 'tenx-hash-vars-extraction')
    - tenx_source_types: List of sourcetypes using 10x (populated at runtime)
    - tenx_sources: List of sources using 10x (populated at runtime)

See Also
--------
- tenx_config.conf: Override these defaults with custom settings
- tenx_util.get_tenx_config(): Loads and merges configuration
"""

# ============================================================================
# Configuration Key Constants
# ============================================================================

# Key in props.conf that references the field extraction transform
# Used to identify which sourcetypes/sources have 10x extraction enabled
TENX_EXTRACTION_NAME = 'tenx_extraction_name'

# The transforms.conf stanza name for 10x encoded event field extraction
# This transform extracts tenx_hash, tenx_var_0, and tenx_vars from encoded events
TENX_EXTRACTION = 'tenx_extraction'

# ============================================================================
# Default Configuration Values
# ============================================================================

DEFAULT_CONFIG = {
	# Index where processed template events (tenx_dml_pure) are stored
	'dest_dml_index':			'main',

	# Sourcetype for processed/searchable template patterns
	'dml_source_type':			'tenx_dml_pure',

	# KV store collection name for template lookup data
	'collection_name':			'kvdml',

	# Placeholder string in patterns where timestamp should be rendered
	# The tenx-inflate macro replaces this with strftime output
	'timestamp_placeholder':	'__TENX_TS__',

	# Character that separates variables in 10x templates
	# Templates look like: $INFO User $ logged in from $
	'variable_separator':		'$',

	# props.conf key name for field extraction reference
	TENX_EXTRACTION_NAME:		'REPORT-tenx',

	# transforms.conf stanza name for encoded event extraction
	TENX_EXTRACTION:				'tenx-hash-vars-extraction',

	# Runtime-populated: sourcetypes with 10x extraction enabled
	'tenx_source_types':			[],

	# Runtime-populated: sources (file paths) with 10x extraction enabled
	'tenx_sources':				[]
}
