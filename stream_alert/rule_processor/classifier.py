"""
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from collections import namedtuple
import json

from stream_alert.rule_processor import LOGGER, LOGGER_DEBUG_ENABLED
from stream_alert.rule_processor.parsers import get_parser
from stream_alert.rule_processor.threat_intel import StreamThreatIntel
from stream_alert.shared.stats import time_me

# Set the below to True when we want to support matching on multiple schemas
# and then log_patterns will be used as a fall back for key/value matching
SUPPORT_MULTIPLE_SCHEMA_MATCHING = False


class StreamClassifier(object):
    """Parse and classify raw record into a declared log."""

    def __init__(self, config):
        self._config = config

    @time_me
    def classify_record(self, payload):
        """Classify and type raw record passed into StreamAlert.

        Before we apply our rules to a record passed to the lambda function,
        we need to validate a record.  Validation requires verifying its source,
        checking that we have declared it in our configuration, and indeitifying
        the record's data source and parsing its data type.

        Args:
            payload: A StreamAlert payload object
        """
        parse_result = self._parse(payload)
        if all([parse_result,
                payload.service(),
                payload.resource,
                payload.type,
                payload.log_source,
                payload.records]):
            payload.valid = True

    @staticmethod
    def _check_schema_match(schema_matches):
        """Check to see if the log matches multiple schemas. If so, fall back
        on using log_patterns to look for the proper log. If no log_patterns
        exist, or they do not resolve the problem, fall back on using the
        first matched schema.

        Args:
            schema_matches (list): A list of tuples containing the info for schemas that have
                validly parsed this record. Each tuple is: (log_name, parser, parsed_data)

        Returns:
            tuple: The proper tuple to use for parsing from the list of tuples
        """
        # If there is only one parse or we do not have support for multiple schemas
        # enabled, then just return the first parse that was valid
        if len(schema_matches) == 1 or not SUPPORT_MULTIPLE_SCHEMA_MATCHING:
            return schema_matches[0]

        matches = []
        for i, schema_match in enumerate(schema_matches):
            log_patterns = schema_match.parser.options.get('log_patterns', {})
            LOGGER.debug('Log patterns: %s', log_patterns)
            if (all(schema_match.parser.matched_log_pattern(data, log_patterns)
                    for data in schema_match.parsed_data)):
                matches.append(schema_matches[i])
            else:
                if LOGGER_DEBUG_ENABLED:
                    LOGGER.debug(
                        'Log pattern matching failed for:\n%s',
                        json.dumps(schema_match.parsed_data, indent=2))

        if matches:
            if len(matches) > 1:
                LOGGER.error('Log patterns matched for multiple schemas: %s',
                             ', '.join(match.log_name for match in matches))
                LOGGER.error('Proceeding with schema for: %s', matches[0].log_name)

            return matches[0]

        LOGGER.error('Log classification matched for multiple schemas: %s',
                     ', '.join(match.log_name for match in schema_matches))
        LOGGER.error('Proceeding with schema for: %s', schema_matches[0].log_name)

        return schema_matches[0]

    @staticmethod
    @time_me
    def _process_log_schemas(payload):
        """Get any log schemas that matched this log format

        Args:
            payload (StreamPayload): The payload to classify

        Returns:
            list: Contains schemas that matched this log format
                Each list entry contains the namedtuple of 'SchemaMatch' with
                values of (log_name, root_schema, parser, and parsed_data)
        """
        schema_match = namedtuple('SchemaMatch',
                                  'log_name, root_schema, parser, parsed_data')
        schema_matches = []

        for log_name, attributes in payload.configured_logs_for_resource.iteritems():
            # Get the parser type to use for this log
            parser_name = payload.type or attributes['parser']

            schema = attributes['schema']
            options = attributes.get('configuration', {})

            # Setup the parser class
            parser_class = get_parser(parser_name)
            parser = parser_class(options)

            # Get a list of parsed records
            LOGGER.debug('Trying schema: %s', log_name)
            parsed_data = parser.parse(schema, payload.pre_parsed_record)

            if not parsed_data:
                continue

            LOGGER.debug('Parsed %d records with schema %s', len(parsed_data), log_name)

            if SUPPORT_MULTIPLE_SCHEMA_MATCHING:
                schema_matches.append(schema_match(log_name, schema, parser, parsed_data))
                continue

            log_patterns = parser.options.get('log_patterns')
            if all(parser.matched_log_pattern(rec, log_patterns) for rec in parsed_data):
                return [schema_match(log_name, schema, parser, parsed_data)]

        return schema_matches

    def _parse(self, payload):
        """Parse a record into a declared type.

        Args:
            payload: A StreamAlert payload object

        Sets:
            payload.log_source: The detected log name from the data_sources config.
            payload.type: The record's type.
            payload.records: The parsed records as a list.

        Returns:
            bool: the success of the parse.
        """
        schema_matches = self._process_log_schemas(payload)

        if not schema_matches:
            return False

        if LOGGER_DEBUG_ENABLED:
            LOGGER.debug('Schema Matched Records:\n%s', json.dumps(
                [schema_match.parsed_data for schema_match in schema_matches], indent=2))

        schema_match = self._check_schema_match(schema_matches)

        if LOGGER_DEBUG_ENABLED:
            LOGGER.debug('Log name: %s', schema_match.log_name)
            LOGGER.debug('Parsed data:\n%s', json.dumps(schema_match.parsed_data, indent=2))

        for parsed_data_value in schema_match.parsed_data:
            # Convert data types per the schema
            # Use the root schema for the parser due to updates caused by
            # configuration settings such as envelope_keys and optional_keys
            if not self._convert_type(
                    parsed_data_value,
                    schema_match.root_schema):
                return False

        normalized_types = StreamThreatIntel.normalized_type_mapping()

        payload.log_source = schema_match.log_name
        payload.type = schema_match.parser.type()
        payload.records = schema_match.parsed_data
        payload.normalized_types = normalized_types.get(payload.log_source.split(':')[0])

        return True

    @classmethod
    def _convert_type(cls, payload, schema):
        """Convert a parsed payload's values into their declared types.

        If the schema is incorrectly defined for a particular field,
        this function will return False which will make the payload
        invalid.

        Args:
            payload (dict): Parsed payload dict
            schema (dict): data schema for a specific log source

        Returns:
            dict: parsed dict payload with typed values
        """
        for key, value in schema.iteritems():
            key = str(key)
            # if the schema value is declared as string
            if value == 'string':
                try:
                    payload[key] = str(payload[key])
                except UnicodeEncodeError:
                    payload[key] = unicode(payload[key])

            # if the schema value is declared as integer
            elif value == 'integer':
                try:
                    payload[key] = int(payload[key])
                except (ValueError, TypeError):
                    LOGGER.error('Invalid schema. Value for key [%s] is not an int: %s',
                                 key, payload[key])
                    return False

            elif value == 'float':
                try:
                    payload[key] = float(payload[key])
                except (ValueError, TypeError):
                    LOGGER.error('Invalid schema. Value for key [%s] is not a float: %s',
                                 key, payload[key])
                    return False

            elif value == 'boolean':
                payload[key] = str(payload[key]).lower() == 'true'

            elif isinstance(value, dict):
                if not value:
                    continue  # allow empty maps (dict)

                # Skip the values for the 'streamalert:envelope_keys' key that we've
                # added during parsing if the do not conform to being a dict
                if key == 'streamalert:envelope_keys' and not isinstance(payload[key], dict):
                    continue

                return cls._convert_type(payload[key], schema[key])

            elif isinstance(value, list):
                pass

            else:
                LOGGER.error('Unsupported schema type: %s', value)

        return True
