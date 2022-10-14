# -*- coding: utf-8 -*-
# Copyright 2022 Google LLC
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
from google.protobuf import timestamp_pb2  # type: ignore
import proto  # type: ignore

__protobuf__ = proto.module(
    package="google.cloud.webrisk.v1",
    manifest={
        "ThreatType",
        "CompressionType",
        "ComputeThreatListDiffRequest",
        "ComputeThreatListDiffResponse",
        "SearchUrisRequest",
        "SearchUrisResponse",
        "SearchHashesRequest",
        "SearchHashesResponse",
        "ThreatEntryAdditions",
        "ThreatEntryRemovals",
        "RawIndices",
        "RawHashes",
        "RiceDeltaEncoding",
        "Submission",
        "CreateSubmissionRequest",
    },
)


class ThreatType(proto.Enum):
    r"""The type of threat. This maps directly to the threat list a
    threat may belong to.
    """
    THREAT_TYPE_UNSPECIFIED = 0
    MALWARE = 1
    SOCIAL_ENGINEERING = 2
    UNWANTED_SOFTWARE = 3
    SOCIAL_ENGINEERING_EXTENDED_COVERAGE = 4


class CompressionType(proto.Enum):
    r"""The ways in which threat entry sets can be compressed."""
    COMPRESSION_TYPE_UNSPECIFIED = 0
    RAW = 1
    RICE = 2


class ComputeThreatListDiffRequest(proto.Message):
    r"""Describes an API diff request.

    Attributes:
        threat_type (google.cloud.webrisk_v1.types.ThreatType):
            Required. The threat list to update. Only a
            single ThreatType should be specified per
            request. If you want to handle multiple
            ThreatTypes, you must make one request per
            ThreatType.
        version_token (bytes):
            The current version token of the client for
            the requested list (the client version that was
            received from the last successful diff). If the
            client does not have a version token (this is
            the first time calling ComputeThreatListDiff),
            this may be left empty and a full database
            snapshot will be returned.
        constraints (google.cloud.webrisk_v1.types.ComputeThreatListDiffRequest.Constraints):
            Required. The constraints associated with
            this request.
    """

    class Constraints(proto.Message):
        r"""The constraints for this diff.

        Attributes:
            max_diff_entries (int):
                The maximum size in number of entries. The diff will not
                contain more entries than this value. This should be a power
                of 2 between 2\ **10 and 2**\ 20. If zero, no diff size
                limit is set.
            max_database_entries (int):
                Sets the maximum number of entries that the client is
                willing to have in the local database. This should be a
                power of 2 between 2\ **10 and 2**\ 20. If zero, no database
                size limit is set.
            supported_compressions (Sequence[google.cloud.webrisk_v1.types.CompressionType]):
                The compression types supported by the
                client.
        """

        max_diff_entries = proto.Field(
            proto.INT32,
            number=1,
        )
        max_database_entries = proto.Field(
            proto.INT32,
            number=2,
        )
        supported_compressions = proto.RepeatedField(
            proto.ENUM,
            number=3,
            enum="CompressionType",
        )

    threat_type = proto.Field(
        proto.ENUM,
        number=1,
        enum="ThreatType",
    )
    version_token = proto.Field(
        proto.BYTES,
        number=2,
    )
    constraints = proto.Field(
        proto.MESSAGE,
        number=3,
        message=Constraints,
    )


class ComputeThreatListDiffResponse(proto.Message):
    r"""

    Attributes:
        response_type (google.cloud.webrisk_v1.types.ComputeThreatListDiffResponse.ResponseType):
            The type of response. This may indicate that
            an action must be taken by the client when the
            response is received.
        additions (google.cloud.webrisk_v1.types.ThreatEntryAdditions):
            A set of entries to add to a local threat
            type's list.
        removals (google.cloud.webrisk_v1.types.ThreatEntryRemovals):
            A set of entries to remove from a local
            threat type's list. This field may be empty.
        new_version_token (bytes):
            The new opaque client version token. This should be retained
            by the client and passed into the next call of
            ComputeThreatListDiff as 'version_token'. A separate version
            token should be stored and used for each threatList.
        checksum (google.cloud.webrisk_v1.types.ComputeThreatListDiffResponse.Checksum):
            The expected SHA256 hash of the client state;
            that is, of the sorted list of all hashes
            present in the database after applying the
            provided diff. If the client state doesn't match
            the expected state, the client must discard this
            diff and retry later.
        recommended_next_diff (google.protobuf.timestamp_pb2.Timestamp):
            The soonest the client should wait before
            issuing any diff request. Querying sooner is
            unlikely to produce a meaningful diff. Waiting
            longer is acceptable considering the use case.
            If this field is not set clients may update as
            soon as they want.
    """

    class ResponseType(proto.Enum):
        r"""The type of response sent to the client."""
        RESPONSE_TYPE_UNSPECIFIED = 0
        DIFF = 1
        RESET = 2

    class Checksum(proto.Message):
        r"""The expected state of a client's local database.

        Attributes:
            sha256 (bytes):
                The SHA256 hash of the client state; that is,
                of the sorted list of all hashes present in the
                database.
        """

        sha256 = proto.Field(
            proto.BYTES,
            number=1,
        )

    response_type = proto.Field(
        proto.ENUM,
        number=4,
        enum=ResponseType,
    )
    additions = proto.Field(
        proto.MESSAGE,
        number=5,
        message="ThreatEntryAdditions",
    )
    removals = proto.Field(
        proto.MESSAGE,
        number=6,
        message="ThreatEntryRemovals",
    )
    new_version_token = proto.Field(
        proto.BYTES,
        number=7,
    )
    checksum = proto.Field(
        proto.MESSAGE,
        number=8,
        message=Checksum,
    )
    recommended_next_diff = proto.Field(
        proto.MESSAGE,
        number=2,
        message=timestamp_pb2.Timestamp,
    )


class SearchUrisRequest(proto.Message):
    r"""Request to check URI entries against threatLists.

    Attributes:
        uri (str):
            Required. The URI to be checked for matches.
        threat_types (Sequence[google.cloud.webrisk_v1.types.ThreatType]):
            Required. The ThreatLists to search in.
            Multiple ThreatLists may be specified.
    """

    uri = proto.Field(
        proto.STRING,
        number=1,
    )
    threat_types = proto.RepeatedField(
        proto.ENUM,
        number=2,
        enum="ThreatType",
    )


class SearchUrisResponse(proto.Message):
    r"""

    Attributes:
        threat (google.cloud.webrisk_v1.types.SearchUrisResponse.ThreatUri):
            The threat list matches. This might be empty
            if the URI is on no list.
    """

    class ThreatUri(proto.Message):
        r"""Contains threat information on a matching uri.

        Attributes:
            threat_types (Sequence[google.cloud.webrisk_v1.types.ThreatType]):
                The ThreatList this threat belongs to.
            expire_time (google.protobuf.timestamp_pb2.Timestamp):
                The cache lifetime for the returned match.
                Clients must not cache this response past this
                timestamp to avoid false positives.
        """

        threat_types = proto.RepeatedField(
            proto.ENUM,
            number=1,
            enum="ThreatType",
        )
        expire_time = proto.Field(
            proto.MESSAGE,
            number=2,
            message=timestamp_pb2.Timestamp,
        )

    threat = proto.Field(
        proto.MESSAGE,
        number=1,
        message=ThreatUri,
    )


class SearchHashesRequest(proto.Message):
    r"""Request to return full hashes matched by the provided hash
    prefixes.

    Attributes:
        hash_prefix (bytes):
            A hash prefix, consisting of the most
            significant 4-32 bytes of a SHA256 hash. For
            JSON requests, this field is base64-encoded.
            Note that if this parameter is provided by a
            URI, it must be encoded using the web safe
            base64 variant (RFC 4648).
        threat_types (Sequence[google.cloud.webrisk_v1.types.ThreatType]):
            Required. The ThreatLists to search in.
            Multiple ThreatLists may be specified.
    """

    hash_prefix = proto.Field(
        proto.BYTES,
        number=1,
    )
    threat_types = proto.RepeatedField(
        proto.ENUM,
        number=2,
        enum="ThreatType",
    )


class SearchHashesResponse(proto.Message):
    r"""

    Attributes:
        threats (Sequence[google.cloud.webrisk_v1.types.SearchHashesResponse.ThreatHash]):
            The full hashes that matched the requested
            prefixes. The hash will be populated in the key.
        negative_expire_time (google.protobuf.timestamp_pb2.Timestamp):
            For requested entities that did not match the
            threat list, how long to cache the response
            until.
    """

    class ThreatHash(proto.Message):
        r"""Contains threat information on a matching hash.

        Attributes:
            threat_types (Sequence[google.cloud.webrisk_v1.types.ThreatType]):
                The ThreatList this threat belongs to.
                This must contain at least one entry.
            hash_ (bytes):
                A 32 byte SHA256 hash. This field is in
                binary format. For JSON requests, hashes are
                base64-encoded.
            expire_time (google.protobuf.timestamp_pb2.Timestamp):
                The cache lifetime for the returned match.
                Clients must not cache this response past this
                timestamp to avoid false positives.
        """

        threat_types = proto.RepeatedField(
            proto.ENUM,
            number=1,
            enum="ThreatType",
        )
        hash_ = proto.Field(
            proto.BYTES,
            number=2,
        )
        expire_time = proto.Field(
            proto.MESSAGE,
            number=3,
            message=timestamp_pb2.Timestamp,
        )

    threats = proto.RepeatedField(
        proto.MESSAGE,
        number=1,
        message=ThreatHash,
    )
    negative_expire_time = proto.Field(
        proto.MESSAGE,
        number=2,
        message=timestamp_pb2.Timestamp,
    )


class ThreatEntryAdditions(proto.Message):
    r"""Contains the set of entries to add to a local database.
    May contain a combination of compressed and raw data in a single
    response.

    Attributes:
        raw_hashes (Sequence[google.cloud.webrisk_v1.types.RawHashes]):
            The raw SHA256-formatted entries.
            Repeated to allow returning sets of hashes with
            different prefix sizes.
        rice_hashes (google.cloud.webrisk_v1.types.RiceDeltaEncoding):
            The encoded 4-byte prefixes of SHA256-formatted entries,
            using a Golomb-Rice encoding. The hashes are converted to
            uint32, sorted in ascending order, then delta encoded and
            stored as encoded_data.
    """

    raw_hashes = proto.RepeatedField(
        proto.MESSAGE,
        number=1,
        message="RawHashes",
    )
    rice_hashes = proto.Field(
        proto.MESSAGE,
        number=2,
        message="RiceDeltaEncoding",
    )


class ThreatEntryRemovals(proto.Message):
    r"""Contains the set of entries to remove from a local database.

    Attributes:
        raw_indices (google.cloud.webrisk_v1.types.RawIndices):
            The raw removal indices for a local list.
        rice_indices (google.cloud.webrisk_v1.types.RiceDeltaEncoding):
            The encoded local, lexicographically-sorted list indices,
            using a Golomb-Rice encoding. Used for sending compressed
            removal indices. The removal indices (uint32) are sorted in
            ascending order, then delta encoded and stored as
            encoded_data.
    """

    raw_indices = proto.Field(
        proto.MESSAGE,
        number=1,
        message="RawIndices",
    )
    rice_indices = proto.Field(
        proto.MESSAGE,
        number=2,
        message="RiceDeltaEncoding",
    )


class RawIndices(proto.Message):
    r"""A set of raw indices to remove from a local list.

    Attributes:
        indices (Sequence[int]):
            The indices to remove from a
            lexicographically-sorted local list.
    """

    indices = proto.RepeatedField(
        proto.INT32,
        number=1,
    )


class RawHashes(proto.Message):
    r"""The uncompressed threat entries in hash format.
    Hashes can be anywhere from 4 to 32 bytes in size. A large
    majority are 4 bytes, but some hashes are lengthened if they
    collide with the hash of a popular URI.

    Used for sending ThreatEntryAdditons to clients that do not
    support compression, or when sending non-4-byte hashes to
    clients that do support compression.

    Attributes:
        prefix_size (int):
            The number of bytes for each prefix encoded
            below.  This field can be anywhere from 4
            (shortest prefix) to 32 (full SHA256 hash). In
            practice this is almost always 4, except in
            exceptional circumstances.
        raw_hashes (bytes):
            The hashes, in binary format, concatenated
            into one long string. Hashes are sorted in
            lexicographic order. For JSON API users, hashes
            are base64-encoded.
    """

    prefix_size = proto.Field(
        proto.INT32,
        number=1,
    )
    raw_hashes = proto.Field(
        proto.BYTES,
        number=2,
    )


class RiceDeltaEncoding(proto.Message):
    r"""The Rice-Golomb encoded data. Used for sending compressed
    4-byte hashes or compressed removal indices.

    Attributes:
        first_value (int):
            The offset of the first entry in the encoded
            data, or, if only a single integer was encoded,
            that single integer's value. If the field is
            empty or missing, assume zero.
        rice_parameter (int):
            The Golomb-Rice parameter, which is a number between 2 and
            28. This field is missing (that is, zero) if ``num_entries``
            is zero.
        entry_count (int):
            The number of entries that are delta encoded in the encoded
            data. If only a single integer was encoded, this will be
            zero and the single value will be stored in ``first_value``.
        encoded_data (bytes):
            The encoded deltas that are encoded using the
            Golomb-Rice coder.
    """

    first_value = proto.Field(
        proto.INT64,
        number=1,
    )
    rice_parameter = proto.Field(
        proto.INT32,
        number=2,
    )
    entry_count = proto.Field(
        proto.INT32,
        number=3,
    )
    encoded_data = proto.Field(
        proto.BYTES,
        number=4,
    )


class Submission(proto.Message):
    r"""Wraps a URI that might be displaying malicious content.

    Attributes:
        uri (str):
            Required. The URI that is being reported for
            malicious content to be analyzed.
    """

    uri = proto.Field(
        proto.STRING,
        number=1,
    )


class CreateSubmissionRequest(proto.Message):
    r"""Request to send a potentially phishy URI to WebRisk.

    Attributes:
        parent (str):
            Required. The name of the project that is making the
            submission. This string is in the format
            "projects/{project_number}".
        submission (google.cloud.webrisk_v1.types.Submission):
            Required. The submission that contains the
            content of the phishing report.
    """

    parent = proto.Field(
        proto.STRING,
        number=1,
    )
    submission = proto.Field(
        proto.MESSAGE,
        number=2,
        message="Submission",
    )


__all__ = tuple(sorted(__protobuf__.manifest))
