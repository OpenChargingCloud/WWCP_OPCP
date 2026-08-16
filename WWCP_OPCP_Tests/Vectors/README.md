# Test vectors

JSON fixtures used by the data-structure tests. Each file records where it came from.

Vectors lifted from the OPCP specification carry a `_source` property naming the OpenAPI document
and the schema or operation whose `example` they were taken from, for instance:

```jsonc
{
  "_source": "libs/OPCP/OPCP-1.0.0/reference/rcp.v1.json — components.schemas.RootCertV2.example",
  ...
}
```

The specification is published by Hubject under **CC BY-SA 4.0**; this repository is AGPL-3.0. The
examples are quoted here as test data, attributed above, and not vendored anywhere else — the
specification itself is read from the `libs/OPCP` submodule rather than copied into this tree.

Vectors we construct ourselves — generated certificates, contract data signed by the test PKI —
carry `"_source": "generated"` and a note on what they exercise.
