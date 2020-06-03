# -*- coding: utf-8 -*-
#
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import google.api_core.grpc_helpers

from google.cloud.webrisk_v1.proto import webrisk_pb2_grpc


class WebRiskServiceGrpcTransport(object):
    """gRPC transport class providing stubs for
    google.cloud.webrisk.v1 WebRiskService API.

    The transport provides access to the raw gRPC stubs,
    which can be used to take advantage of advanced
    features of gRPC.
    """

    # The scopes needed to make gRPC calls to all of the methods defined
    # in this service.
    _OAUTH_SCOPES = ("https://www.googleapis.com/auth/cloud-platform",)

    def __init__(
        self, channel=None, credentials=None, address="webrisk.googleapis.com:443"
    ):
        """Instantiate the transport class.

        Args:
            channel (grpc.Channel): A ``Channel`` instance through
                which to make calls. This argument is mutually exclusive
                with ``credentials``; providing both will raise an exception.
            credentials (google.auth.credentials.Credentials): The
                authorization credentials to attach to requests. These
                credentials identify this application to the service. If none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
            address (str): The address where the service is hosted.
        """
        # If both `channel` and `credentials` are specified, raise an
        # exception (channels come with credentials baked in already).
        if channel is not None and credentials is not None:
            raise ValueError(
                "The `channel` and `credentials` arguments are mutually " "exclusive."
            )

        # Create the channel.
        if channel is None:
            channel = self.create_channel(
                address=address,
                credentials=credentials,
                options={
                    "grpc.max_send_message_length": -1,
                    "grpc.max_receive_message_length": -1,
                }.items(),
            )

        self._channel = channel

        # gRPC uses objects called "stubs" that are bound to the
        # channel and provide a basic method for each RPC.
        self._stubs = {
            "web_risk_service_stub": webrisk_pb2_grpc.WebRiskServiceStub(channel)
        }

    @classmethod
    def create_channel(
        cls, address="webrisk.googleapis.com:443", credentials=None, **kwargs
    ):
        """Create and return a gRPC channel object.

        Args:
            address (str): The host for the channel to use.
            credentials (~.Credentials): The
                authorization credentials to attach to requests. These
                credentials identify this application to the service. If
                none are specified, the client will attempt to ascertain
                the credentials from the environment.
            kwargs (dict): Keyword arguments, which are passed to the
                channel creation.

        Returns:
            grpc.Channel: A gRPC channel object.
        """
        return google.api_core.grpc_helpers.create_channel(
            address, credentials=credentials, scopes=cls._OAUTH_SCOPES, **kwargs
        )

    @property
    def channel(self):
        """The gRPC channel used by the transport.

        Returns:
            grpc.Channel: A gRPC channel object.
        """
        return self._channel

    @property
    def compute_threat_list_diff(self):
        """Return the gRPC stub for :meth:`WebRiskServiceClient.compute_threat_list_diff`.

        Gets the most recent threat list diffs. These diffs should be applied to
        a local database of hashes to keep it up-to-date. If the local database is
        empty or excessively out-of-date, a complete snapshot of the database will
        be returned. This Method only updates a single ThreatList at a time. To
        update multiple ThreatList databases, this method needs to be called once
        for each list.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["web_risk_service_stub"].ComputeThreatListDiff

    @property
    def search_uris(self):
        """Return the gRPC stub for :meth:`WebRiskServiceClient.search_uris`.

        This method is used to check whether a URI is on a given threatList.
        Multiple threatLists may be searched in a single query.
        The response will list all requested threatLists the URI was found to
        match. If the URI is not found on any of the requested ThreatList an
        empty response will be returned.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["web_risk_service_stub"].SearchUris

    @property
    def search_hashes(self):
        """Return the gRPC stub for :meth:`WebRiskServiceClient.search_hashes`.

        Gets the full hashes that match the requested hash prefix.
        This is used after a hash prefix is looked up in a threatList
        and there is a match. The client side threatList only holds partial hashes
        so the client must query this method to determine if there is a full
        hash match of a threat.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["web_risk_service_stub"].SearchHashes

    @property
    def create_submission(self):
        """Return the gRPC stub for :meth:`WebRiskServiceClient.create_submission`.

        Creates a Submission of a URI suspected of containing phishing
        content to be reviewed. If the result verifies the existence of
        malicious phishing content, the site will be added to the `Google's
        Social Engineering
        lists <https://support.google.com/webmasters/answer/6350487/>`__ in
        order to protect users that could get exposed to this threat in the
        future. Only projects with CREATE_SUBMISSION_USERS visibility can use
        this method.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["web_risk_service_stub"].CreateSubmission
