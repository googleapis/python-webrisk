# -*- coding: utf-8 -*-

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
from unittest import mock

import grpc
import math
import pytest

from google import auth
from google.api_core import client_options
from google.api_core import grpc_helpers
from google.auth import credentials
from google.auth.exceptions import MutualTLSChannelError
from google.cloud.webrisk_v1.services.web_risk_service import WebRiskServiceClient
from google.cloud.webrisk_v1.services.web_risk_service import transports
from google.cloud.webrisk_v1.types import webrisk
from google.oauth2 import service_account
from google.protobuf import timestamp_pb2 as timestamp  # type: ignore


def client_cert_source_callback():
    return b"cert bytes", b"key bytes"


def test__get_default_mtls_endpoint():
    api_endpoint = "example.googleapis.com"
    api_mtls_endpoint = "example.mtls.googleapis.com"
    sandbox_endpoint = "example.sandbox.googleapis.com"
    sandbox_mtls_endpoint = "example.mtls.sandbox.googleapis.com"
    non_googleapi = "api.example.com"

    assert WebRiskServiceClient._get_default_mtls_endpoint(None) is None
    assert WebRiskServiceClient._get_default_mtls_endpoint(api_endpoint) == api_mtls_endpoint
    assert WebRiskServiceClient._get_default_mtls_endpoint(api_mtls_endpoint) == api_mtls_endpoint
    assert WebRiskServiceClient._get_default_mtls_endpoint(sandbox_endpoint) == sandbox_mtls_endpoint
    assert WebRiskServiceClient._get_default_mtls_endpoint(sandbox_mtls_endpoint) == sandbox_mtls_endpoint
    assert WebRiskServiceClient._get_default_mtls_endpoint(non_googleapi) == non_googleapi


def test_web_risk_service_client_from_service_account_file():
    creds = credentials.AnonymousCredentials()
    with mock.patch.object(service_account.Credentials, 'from_service_account_file') as factory:
        factory.return_value = creds
        client = WebRiskServiceClient.from_service_account_file("dummy/file/path.json")
        assert client._transport._credentials == creds

        client = WebRiskServiceClient.from_service_account_json("dummy/file/path.json")
        assert client._transport._credentials == creds

        assert client._transport._host == 'webrisk.googleapis.com:443'


def test_web_risk_service_client_get_transport_class():
    transport = WebRiskServiceClient.get_transport_class()
    assert transport == transports.WebRiskServiceGrpcTransport

    transport = WebRiskServiceClient.get_transport_class("grpc")
    assert transport == transports.WebRiskServiceGrpcTransport


def test_web_risk_service_client_client_options():
    # Check that if channel is provided we won't create a new one.
    with mock.patch('google.cloud.webrisk_v1.services.web_risk_service.WebRiskServiceClient.get_transport_class') as gtc:
        transport = transports.WebRiskServiceGrpcTransport(
            credentials=credentials.AnonymousCredentials()
        )
        client = WebRiskServiceClient(transport=transport)
        gtc.assert_not_called()

    # Check that if channel is provided via str we will create a new one.
    with mock.patch('google.cloud.webrisk_v1.services.web_risk_service.WebRiskServiceClient.get_transport_class') as gtc:
        client = WebRiskServiceClient(transport="grpc")
        gtc.assert_called()

    # Check the case api_endpoint is provided.
    options = client_options.ClientOptions(api_endpoint="squid.clam.whelk")
    with mock.patch('google.cloud.webrisk_v1.services.web_risk_service.transports.WebRiskServiceGrpcTransport.__init__') as grpc_transport:
        grpc_transport.return_value = None
        client = WebRiskServiceClient(client_options=options)
        grpc_transport.assert_called_once_with(
            api_mtls_endpoint="squid.clam.whelk",
            client_cert_source=None,
            credentials=None,
            host="squid.clam.whelk",
        )

    # Check the case api_endpoint is not provided and GOOGLE_API_USE_MTLS is
    # "never".
    os.environ["GOOGLE_API_USE_MTLS"] = "never"
    with mock.patch('google.cloud.webrisk_v1.services.web_risk_service.transports.WebRiskServiceGrpcTransport.__init__') as grpc_transport:
        grpc_transport.return_value = None
        client = WebRiskServiceClient()
        grpc_transport.assert_called_once_with(
            api_mtls_endpoint=client.DEFAULT_ENDPOINT,
            client_cert_source=None,
            credentials=None,
            host=client.DEFAULT_ENDPOINT,
        )

    # Check the case api_endpoint is not provided and GOOGLE_API_USE_MTLS is
    # "always".
    os.environ["GOOGLE_API_USE_MTLS"] = "always"
    with mock.patch('google.cloud.webrisk_v1.services.web_risk_service.transports.WebRiskServiceGrpcTransport.__init__') as grpc_transport:
        grpc_transport.return_value = None
        client = WebRiskServiceClient()
        grpc_transport.assert_called_once_with(
            api_mtls_endpoint=client.DEFAULT_MTLS_ENDPOINT,
            client_cert_source=None,
            credentials=None,
            host=client.DEFAULT_MTLS_ENDPOINT,
        )

    # Check the case api_endpoint is not provided, GOOGLE_API_USE_MTLS is
    # "auto", and client_cert_source is provided.
    os.environ["GOOGLE_API_USE_MTLS"] = "auto"
    options = client_options.ClientOptions(client_cert_source=client_cert_source_callback)
    with mock.patch('google.cloud.webrisk_v1.services.web_risk_service.transports.WebRiskServiceGrpcTransport.__init__') as grpc_transport:
        grpc_transport.return_value = None
        client = WebRiskServiceClient(client_options=options)
        grpc_transport.assert_called_once_with(
            api_mtls_endpoint=client.DEFAULT_MTLS_ENDPOINT,
            client_cert_source=client_cert_source_callback,
            credentials=None,
            host=client.DEFAULT_MTLS_ENDPOINT,
        )

    # Check the case api_endpoint is not provided, GOOGLE_API_USE_MTLS is
    # "auto", and default_client_cert_source is provided.
    os.environ["GOOGLE_API_USE_MTLS"] = "auto"
    with mock.patch('google.cloud.webrisk_v1.services.web_risk_service.transports.WebRiskServiceGrpcTransport.__init__') as grpc_transport:
        with mock.patch('google.auth.transport.mtls.has_default_client_cert_source', return_value=True):
            grpc_transport.return_value = None
            client = WebRiskServiceClient()
            grpc_transport.assert_called_once_with(
                api_mtls_endpoint=client.DEFAULT_MTLS_ENDPOINT,
                client_cert_source=None,
                credentials=None,
                host=client.DEFAULT_MTLS_ENDPOINT,
            )

    # Check the case api_endpoint is not provided, GOOGLE_API_USE_MTLS is
    # "auto", but client_cert_source and default_client_cert_source are None.
    os.environ["GOOGLE_API_USE_MTLS"] = "auto"
    with mock.patch('google.cloud.webrisk_v1.services.web_risk_service.transports.WebRiskServiceGrpcTransport.__init__') as grpc_transport:
        with mock.patch('google.auth.transport.mtls.has_default_client_cert_source', return_value=False):
            grpc_transport.return_value = None
            client = WebRiskServiceClient()
            grpc_transport.assert_called_once_with(
                api_mtls_endpoint=client.DEFAULT_ENDPOINT,
                client_cert_source=None,
                credentials=None,
                host=client.DEFAULT_ENDPOINT,
            )

    # Check the case api_endpoint is not provided and GOOGLE_API_USE_MTLS has
    # unsupported value.
    os.environ["GOOGLE_API_USE_MTLS"] = "Unsupported"
    with pytest.raises(MutualTLSChannelError):
        client = WebRiskServiceClient()

    del os.environ["GOOGLE_API_USE_MTLS"]


def test_web_risk_service_client_client_options_from_dict():
    with mock.patch('google.cloud.webrisk_v1.services.web_risk_service.transports.WebRiskServiceGrpcTransport.__init__') as grpc_transport:
        grpc_transport.return_value = None
        client = WebRiskServiceClient(
            client_options={'api_endpoint': 'squid.clam.whelk'}
        )
        grpc_transport.assert_called_once_with(
            api_mtls_endpoint="squid.clam.whelk",
            client_cert_source=None,
            credentials=None,
            host="squid.clam.whelk",
        )


def test_compute_threat_list_diff(transport: str = 'grpc'):
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = webrisk.ComputeThreatListDiffRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
            type(client._transport.compute_threat_list_diff),
            '__call__') as call:
        # Designate an appropriate return value for the call.
        call.return_value = webrisk.ComputeThreatListDiffResponse(
            response_type=webrisk.ComputeThreatListDiffResponse.ResponseType.DIFF,
            new_version_token=b'new_version_token_blob',
        )

        response = client.compute_threat_list_diff(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, webrisk.ComputeThreatListDiffResponse)
    assert response.response_type == webrisk.ComputeThreatListDiffResponse.ResponseType.DIFF
    assert response.new_version_token == b'new_version_token_blob'


def test_compute_threat_list_diff_flattened():
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
            type(client._transport.compute_threat_list_diff),
            '__call__') as call:
        # Designate an appropriate return value for the call.
        call.return_value = webrisk.ComputeThreatListDiffResponse()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.compute_threat_list_diff(
            threat_type=webrisk.ThreatType.MALWARE,
            version_token=b'version_token_blob',
            constraints=webrisk.ComputeThreatListDiffRequest.Constraints(max_diff_entries=1687),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0].threat_type == webrisk.ThreatType.MALWARE
        assert args[0].version_token == b'version_token_blob'
        assert args[0].constraints == webrisk.ComputeThreatListDiffRequest.Constraints(max_diff_entries=1687)


def test_compute_threat_list_diff_flattened_error():
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.compute_threat_list_diff(
            webrisk.ComputeThreatListDiffRequest(),
            threat_type=webrisk.ThreatType.MALWARE,
            version_token=b'version_token_blob',
            constraints=webrisk.ComputeThreatListDiffRequest.Constraints(max_diff_entries=1687),
        )


def test_search_uris(transport: str = 'grpc'):
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = webrisk.SearchUrisRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
            type(client._transport.search_uris),
            '__call__') as call:
        # Designate an appropriate return value for the call.
        call.return_value = webrisk.SearchUrisResponse(
        )

        response = client.search_uris(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, webrisk.SearchUrisResponse)


def test_search_uris_flattened():
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
            type(client._transport.search_uris),
            '__call__') as call:
        # Designate an appropriate return value for the call.
        call.return_value = webrisk.SearchUrisResponse()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.search_uris(
            uri='uri_value',
            threat_types=[webrisk.ThreatType.MALWARE],
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0].uri == 'uri_value'
        assert args[0].threat_types == [webrisk.ThreatType.MALWARE]


def test_search_uris_flattened_error():
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.search_uris(
            webrisk.SearchUrisRequest(),
            uri='uri_value',
            threat_types=[webrisk.ThreatType.MALWARE],
        )


def test_search_hashes(transport: str = 'grpc'):
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = webrisk.SearchHashesRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
            type(client._transport.search_hashes),
            '__call__') as call:
        # Designate an appropriate return value for the call.
        call.return_value = webrisk.SearchHashesResponse(
        )

        response = client.search_hashes(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, webrisk.SearchHashesResponse)


def test_search_hashes_flattened():
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
            type(client._transport.search_hashes),
            '__call__') as call:
        # Designate an appropriate return value for the call.
        call.return_value = webrisk.SearchHashesResponse()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.search_hashes(
            hash_prefix=b'hash_prefix_blob',
            threat_types=[webrisk.ThreatType.MALWARE],
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0].hash_prefix == b'hash_prefix_blob'
        assert args[0].threat_types == [webrisk.ThreatType.MALWARE]


def test_search_hashes_flattened_error():
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.search_hashes(
            webrisk.SearchHashesRequest(),
            hash_prefix=b'hash_prefix_blob',
            threat_types=[webrisk.ThreatType.MALWARE],
        )


def test_create_submission(transport: str = 'grpc'):
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = webrisk.CreateSubmissionRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
            type(client._transport.create_submission),
            '__call__') as call:
        # Designate an appropriate return value for the call.
        call.return_value = webrisk.Submission(
            uri='uri_value',
        )

        response = client.create_submission(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, webrisk.Submission)
    assert response.uri == 'uri_value'


def test_create_submission_field_headers():
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = webrisk.CreateSubmissionRequest()
    request.parent = 'parent/value'

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
            type(client._transport.create_submission),
            '__call__') as call:
        call.return_value = webrisk.Submission()

        client.create_submission(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert (
        'x-goog-request-params',
        'parent=parent/value',
    ) in kw['metadata']


def test_create_submission_flattened():
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
            type(client._transport.create_submission),
            '__call__') as call:
        # Designate an appropriate return value for the call.
        call.return_value = webrisk.Submission()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.create_submission(
            parent='parent_value',
            submission=webrisk.Submission(uri='uri_value'),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0].parent == 'parent_value'
        assert args[0].submission == webrisk.Submission(uri='uri_value')


def test_create_submission_flattened_error():
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.create_submission(
            webrisk.CreateSubmissionRequest(),
            parent='parent_value',
            submission=webrisk.Submission(uri='uri_value'),
        )


def test_credentials_transport_error():
    # It is an error to provide credentials and a transport instance.
    transport = transports.WebRiskServiceGrpcTransport(
        credentials=credentials.AnonymousCredentials(),
    )
    with pytest.raises(ValueError):
        client = WebRiskServiceClient(
            credentials=credentials.AnonymousCredentials(),
            transport=transport,
        )


def test_transport_instance():
    # A client may be instantiated with a custom transport instance.
    transport = transports.WebRiskServiceGrpcTransport(
        credentials=credentials.AnonymousCredentials(),
    )
    client = WebRiskServiceClient(transport=transport)
    assert client._transport is transport


def test_transport_grpc_default():
    # A client should use the gRPC transport by default.
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
    )
    assert isinstance(
        client._transport,
        transports.WebRiskServiceGrpcTransport,
    )


def test_web_risk_service_base_transport():
    # Instantiate the base transport.
    transport = transports.WebRiskServiceTransport(
        credentials=credentials.AnonymousCredentials(),
    )

    # Every method on the transport should just blindly
    # raise NotImplementedError.
    methods = (
        'compute_threat_list_diff',
        'search_uris',
        'search_hashes',
        'create_submission',
        )
    for method in methods:
        with pytest.raises(NotImplementedError):
            getattr(transport, method)(request=object())


def test_web_risk_service_auth_adc():
    # If no credentials are provided, we should use ADC credentials.
    with mock.patch.object(auth, 'default') as adc:
        adc.return_value = (credentials.AnonymousCredentials(), None)
        WebRiskServiceClient()
        adc.assert_called_once_with(scopes=(
            'https://www.googleapis.com/auth/cloud-platform',
        ))


def test_web_risk_service_transport_auth_adc():
    # If credentials and host are not provided, the transport class should use
    # ADC credentials.
    with mock.patch.object(auth, 'default') as adc:
        adc.return_value = (credentials.AnonymousCredentials(), None)
        transports.WebRiskServiceGrpcTransport(host="squid.clam.whelk")
        adc.assert_called_once_with(scopes=(
            'https://www.googleapis.com/auth/cloud-platform',
        ))


def test_web_risk_service_host_no_port():
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
        client_options=client_options.ClientOptions(api_endpoint='webrisk.googleapis.com'),
    )
    assert client._transport._host == 'webrisk.googleapis.com:443'


def test_web_risk_service_host_with_port():
    client = WebRiskServiceClient(
        credentials=credentials.AnonymousCredentials(),
        client_options=client_options.ClientOptions(api_endpoint='webrisk.googleapis.com:8000'),
    )
    assert client._transport._host == 'webrisk.googleapis.com:8000'


def test_web_risk_service_grpc_transport_channel():
    channel = grpc.insecure_channel('http://localhost/')

    # Check that if channel is provided, mtls endpoint and client_cert_source
    # won't be used.
    callback = mock.MagicMock()
    transport = transports.WebRiskServiceGrpcTransport(
        host="squid.clam.whelk",
        channel=channel,
        api_mtls_endpoint="mtls.squid.clam.whelk",
        client_cert_source=callback,
    )
    assert transport.grpc_channel == channel
    assert transport._host == "squid.clam.whelk:443"
    assert not callback.called


@mock.patch("grpc.ssl_channel_credentials", autospec=True)
@mock.patch("google.api_core.grpc_helpers.create_channel", autospec=True)
def test_web_risk_service_grpc_transport_channel_mtls_with_client_cert_source(
    grpc_create_channel, grpc_ssl_channel_cred
):
    # Check that if channel is None, but api_mtls_endpoint and client_cert_source
    # are provided, then a mTLS channel will be created.
    mock_cred = mock.Mock()

    mock_ssl_cred = mock.Mock()
    grpc_ssl_channel_cred.return_value = mock_ssl_cred

    mock_grpc_channel = mock.Mock()
    grpc_create_channel.return_value = mock_grpc_channel

    transport = transports.WebRiskServiceGrpcTransport(
        host="squid.clam.whelk",
        credentials=mock_cred,
        api_mtls_endpoint="mtls.squid.clam.whelk",
        client_cert_source=client_cert_source_callback,
    )
    grpc_ssl_channel_cred.assert_called_once_with(
        certificate_chain=b"cert bytes", private_key=b"key bytes"
    )
    grpc_create_channel.assert_called_once_with(
        "mtls.squid.clam.whelk:443",
        credentials=mock_cred,
        ssl_credentials=mock_ssl_cred,
        scopes=(
            'https://www.googleapis.com/auth/cloud-platform',
        ),
    )
    assert transport.grpc_channel == mock_grpc_channel


@pytest.mark.parametrize(
    "api_mtls_endpoint", ["mtls.squid.clam.whelk", "mtls.squid.clam.whelk:443"]
)
@mock.patch("google.api_core.grpc_helpers.create_channel", autospec=True)
def test_web_risk_service_grpc_transport_channel_mtls_with_adc(
    grpc_create_channel, api_mtls_endpoint
):
    # Check that if channel and client_cert_source are None, but api_mtls_endpoint
    # is provided, then a mTLS channel will be created with SSL ADC.
    mock_grpc_channel = mock.Mock()
    grpc_create_channel.return_value = mock_grpc_channel

    # Mock google.auth.transport.grpc.SslCredentials class.
    mock_ssl_cred = mock.Mock()
    with mock.patch.multiple(
        "google.auth.transport.grpc.SslCredentials",
        __init__=mock.Mock(return_value=None),
        ssl_credentials=mock.PropertyMock(return_value=mock_ssl_cred),
    ):
        mock_cred = mock.Mock()
        transport = transports.WebRiskServiceGrpcTransport(
            host="squid.clam.whelk",
            credentials=mock_cred,
            api_mtls_endpoint=api_mtls_endpoint,
            client_cert_source=None,
        )
        grpc_create_channel.assert_called_once_with(
            "mtls.squid.clam.whelk:443",
            credentials=mock_cred,
            ssl_credentials=mock_ssl_cred,
            scopes=(
                'https://www.googleapis.com/auth/cloud-platform',
            ),
        )
        assert transport.grpc_channel == mock_grpc_channel
