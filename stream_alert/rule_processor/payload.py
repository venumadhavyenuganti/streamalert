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
from abc import ABCMeta, abstractmethod, abstractproperty
import base64
from collections import namedtuple, OrderedDict
import gzip
from logging import DEBUG as LOG_LEVEL_DEBUG
import os
import tempfile
import time
from urllib import unquote
import zlib

import boto3

from stream_alert.rule_processor import FUNCTION_NAME, LOGGER
from stream_alert.shared.metrics import MetricLogger

SERVICE = namedtuple('ServiceMapper', 'payload_class extract_resource')


def load_stream_payload(raw_record):
    """Returns the right StreamPayload subclass for this service

    Args:
        raw_record (str): record raw payload data
    """
    # Keys are capitalized per logs from each service
    payload_mapper = {
        'kinesis': SERVICE(
            KinesisPayload,
            lambda r: r['eventSourceARN'].split('/')[1]),
        's3': SERVICE(
            S3Payload,
            lambda r: r['s3']['bucket']['name']),
        'Sns': SERVICE(
            SnsPayload,
            lambda r: r['EventSubscriptionArn'].split(':')[5]),
        'stream_alert_app': SERVICE(
            StreamAlertAppPayload,
            lambda r: r['stream_alert_app'])}

    # Set default strings for service and resource
    service, resource = '', ''

    # Extract the service (kinesis, s3, sns, etc) and resource (stream name, s3 bucket, etc)
    # from the raw record
    for service_name, service_mapper in payload_mapper.iteritems():
        if service_name in raw_record:
            service = service_name
            resource = service_mapper.extract_resource(raw_record)
            break

    if not service:
        LOGGER.error('Unsupported service found, skipping...\n%s', raw_record)
        return False

    if not resource:
        LOGGER.error('Unable to extract the resource of %s from the record %s', service, raw_record)
        return False

    # Create the payload object
    return payload_mapper[service].payload_class(raw_record=raw_record, resource=resource)


class StreamPayload(object):
    """Container class for the StreamAlert payload object.

    Attributes:
        service (str): The originating service used to deliver the log.
        resource (str): A resource to a service - Kinesis stream, SNS topic, S3 bucket, etc.
        raw_record (dict): An unparsed record passed into the Lambda handler.
        log_source (str): The name of the classified log where data originated from.
        records (list): A list of parsed and typed records.
        type (str): The data type of the parsed record. Could be json, csv, syslog, etc.
        valid (bool): Whether the record is deemed valid by parsing and classification.
    """
    __metaclass__ = ABCMeta

    def __init__(self, **kwargs):
        """
        Keyword Args:
            raw_record (dict): The record to be parsed - in AWS event format
        """
        # Set preliminary attributes
        self.raw_record = kwargs['raw_record']
        self.resource = kwargs['resource']
        self.pre_parsed_record = None
        self.configured_logs_for_resource = None
        self._resource_exclude_expressions = None

        # Prepare the payload
        self._refresh_record()

    def __repr__(self):
        repr_str = ('<{} valid:{} log_source:{} resource:{} '
                    'type:{} record:{}>').format(self.__class__.__name__, self.valid,
                                                 self.log_source, self.resource, self.type,
                                                 self.records)

        return repr_str

    @abstractproperty
    def service(self):
        """The AWS service the payload originated from.

        Returns:
            str: The service name for this payload type.
        """

    @abstractmethod
    def pre_parse(self):
        """Pre-parsing method that should be implemented by all subclasses.
        This establishes the `pre_parsed_record` property to allow for parsing.

        Yields:
            Instances of `self` back to the caller with the
                proper `pre_parsed_record` set. Conforming to the interface of
                returning a generator provides the ability to support multi-record
                payloads, such as those similar to S3.
        """

    def _refresh_record(self, new_record=None):
        """Replace the currently loaded record with a new one.

        Used mainly when S3 is used as a source, due to looping over files
        downloaded from S3 events versus all records being readily available
        from a Kinesis stream.

        Args:
            new_record (str): A new raw record to be parsed
        """
        self.pre_parsed_record = new_record
        self.log_source = None
        self.records = None
        self.type = None
        self.valid = False

    def load_logs_for_source(self, config):
        """Load a mapping of all potential logs for the payload's resource

        Args:
            config (dict): The loaded StreamAlert config
        """
        resources_for_service = config['sources'].get(self.service())
        if not resources_for_service:
            LOGGER.error('Service [%s] not declared in sources.json configuration', self.service())
            return False

        resource_log_config = resources_for_service.get(self.resource)
        if not resource_log_config:
            LOGGER.error(
                'Resource [%s] not declared in sources.json configuration for service [%s]',
                self.resource, self.service())
            return False

        # Load custom configuration settings here
        self._resource_exclude_expressions = resource_log_config.get('exclude', [])

        self.configured_logs_for_resource = OrderedDict(
            (log_name, config['logs'][log_name]) for log_name in config['logs'].keys()
            if log_name.split(':')[0] in resource_log_config['logs'])

        return bool(self.configured_logs_for_resource)


class S3ObjectSizeError(Exception):
    """Exception indicating the S3 object is too large to process"""


class S3Payload(StreamPayload):
    """S3Payload class"""
    s3_object_size = 0

    def service(self):
        return 's3'

    def pre_parse(self):
        """Pre-parsing method for S3 objects that will download the s3 object,
        open it for reading and iterate over lines (records) in the file.
        This yields back references of this S3Payload instance to the caller
        with a propertly set `pre_parsed_record` for this record.

        Yields:
            Instances of `self` back to the caller with the
                proper `pre_parsed_record` set. Conforms to the interface of
                returning a generator, providing the ability to support
                multi-record like this (s3).
        """
        s3_file_path = self._get_object()
        if not s3_file_path:
            return

        line_num, processed_size = 0, 0
        for line_num, data in self._read_downloaded_s3_object(s3_file_path):

            self._refresh_record(data)
            yield self

            # Only do the extra calculations below if debug logging is enabled
            if not LOGGER.isEnabledFor(LOG_LEVEL_DEBUG):
                continue

            # Add the current data to the total processed size
            # +1 to account for line feed
            processed_size += (len(data) + 1)

            # Log a debug message on every 100 lines processed
            if line_num % 100 == 0:
                avg_record_size = ((processed_size - 1) / line_num)
                if avg_record_size:
                    approx_record_count = self.s3_object_size / avg_record_size
                    LOGGER.debug('Processed %s S3 records out of an approximate total of %s '
                                 '(average record size: %s bytes, total size: %s bytes)', line_num,
                                 approx_record_count, avg_record_size, self.s3_object_size)

        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.TOTAL_S3_RECORDS, line_num)

    def _download_object(self, region, bucket, key):
        """Download an object from S3.

        Verifies the S3 object is less than or equal to 128MB, and
        downloads it into a temp file.  Lambda can only execute for a
        maximum of 300 seconds, and the file to download
        greatly impacts that time.

        Args:
            region (str): AWS region to use for boto client instance.
            bucket (str): S3 bucket to download object from.
            key (str): Key of s3 object.

        Returns:
            str: The downloaded path of the S3 object.
        """
        size_kb = self.s3_object_size / 1024.0
        size_mb = size_kb / 1024.0

        # File size checks before downloading
        if size_kb == 0:
            return
        elif size_mb > 128:
            raise S3ObjectSizeError('S3 object to download is above 128MB')

        # Bandit warns about using a shell process, ignore with #nosec
        LOGGER.debug(os.popen('df -h /tmp | tail -1').read().strip())  # nosec

        display_size = '{}MB'.format(size_mb) if size_mb else '{}KB'.format(size_kb)

        LOGGER.info('Starting download from S3: %s/%s [%s]', bucket, key, display_size)

        # Convert the S3 object name to store as a file in the Lambda container
        suffix = key.replace('/', '-')
        _, downloaded_s3_object = tempfile.mkstemp(suffix=suffix)

        with open(downloaded_s3_object, 'wb') as data:
            client = boto3.client('s3', region_name=region)
            start_time = time.time()
            client.download_fileobj(bucket, key, data)

        total_time = time.time() - start_time
        LOGGER.info('Completed download in %s seconds', round(total_time, 2))

        # Log a metric on how long this object took to download
        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.S3_DOWNLOAD_TIME, total_time)

        return downloaded_s3_object

    def _get_object(self):
        """Given an S3 record, download and parse the data.

        Returns:
            str: Path to the downloaded s3 object.
        """
        # Use the urllib unquote method to decode any url encoded characters
        # (ie - %26 --> &) from the bucket and key names
        unquoted = lambda(data): unquote(data).decode('utf-8')
        region = self.raw_record['awsRegion']

        bucket = unquoted(self.raw_record['s3']['bucket']['name'])
        key = unquoted(self.raw_record['s3']['object']['key'])
        self.s3_object_size = int(self.raw_record['s3']['object']['size'])

        LOGGER.debug('Pre-parsing record from S3. Bucket: %s, Key: %s, Size: %d', bucket, key,
                     self.s3_object_size)

        return self._download_object(region, bucket, key)

    @staticmethod
    def _read_downloaded_s3_object(s3_object):
        """Read lines from a downloaded file from S3

        Supports reading both gzipped files and plaintext files.

        Args:
            s3_object (str): A full path to the downloaded file.

        Yields:
            (str) Lines from the downloaded s3 object.
        """
        _, extension = os.path.splitext(s3_object)

        if extension == '.gz':
            for num, line in enumerate(gzip.open(s3_object, 'r'), start=1):
                yield num, line.rstrip()
        else:
            for num, line in enumerate(open(s3_object, 'r'), start=1):
                yield num, line.rstrip()

        # AWS Lambda apparently does not reallocate disk space when files are
        # removed using os.remove(), so we must truncate them before removal
        open(s3_object, 'w')

        os.remove(s3_object)
        if not os.path.exists(s3_object):
            LOGGER.debug('Removed temp S3 file: %s', s3_object)
        else:
            LOGGER.error('Failed to remove temp S3 file: %s', s3_object)


class SnsPayload(StreamPayload):
    """SnsPayload class"""

    def service(self):
        return 'sns'

    def pre_parse(self):
        """Pre-parsing method for SNS records. Extracts the SNS payload from the
        record itself and sets it as the `pre_parsed_record` property.

        Yields:
            This object with the pre_parsed_record now set
        """
        LOGGER.debug('Pre-parsing record from SNS. MessageId: %s, EventSubscriptionArn: %s',
                     self.raw_record['Sns']['MessageId'], self.raw_record['EventSubscriptionArn'])

        self.pre_parsed_record = self.raw_record['Sns']['Message']

        yield self


class KinesisPayload(StreamPayload):
    """KinesisPayload class"""

    def service(self):
        return 'kinesis'

    def pre_parse(self):
        """Pre-parsing method for Kinesis records. Extracts the base64 encoded
        payload from the record itself, decodes it and sets it as the
        `pre_parsed_record` property.

        Yields:
            This object with the pre_parsed_record now set
        """
        LOGGER.debug('Pre-parsing record from Kinesis. eventID: %s, eventSourceARN: %s',
                     self.raw_record['eventID'], self.raw_record['eventSourceARN'])

        # Kinesis records have to potential to be gzipped, so try to decompress
        record = base64.b64decode(self.raw_record['kinesis']['data'])
        try:
            self.pre_parsed_record = zlib.decompress(record, 47)
        except zlib.error:
            self.pre_parsed_record = record

        yield self


class StreamAlertAppPayload(StreamPayload):
    """StreamAlertAppPayload class"""

    def service(self):
        return 'stream_alert_app'

    def pre_parse(self):
        """Pre-parsing method for incoming app records that iterates over all the
        incoming logs in the 'logs' list.

        Yields:
            Instances of `self` back to the caller with the proper
                `pre_parsed_record` set to the current log data. This conforms
                to the interface of returning a generator, providing the ability
                to support multiple records like this.
        """
        for data in self.raw_record['logs']:

            self._refresh_record(data)
            yield self

        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.TOTAL_STREAM_ALERT_APP_RECORDS,
                                len(self.raw_record['logs']))
