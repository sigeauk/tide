"""CTI fetchers — pull intel from external sources into per-tenant CTI DBs.

5.0.0: the legacy OpenCTI GraphQL fetcher has been removed entirely.
All CTI ingest now flows through the multi-vendor TAXII 2.1 framework
under :mod:`app.services.cti_connectors` and the shared TAXII engine
in :mod:`app.services.cti_fetchers.taxii21`. New vendors register a
``ConnectorVendor`` in ``cti_connectors`` rather than reimplementing
a fetcher here.
"""

