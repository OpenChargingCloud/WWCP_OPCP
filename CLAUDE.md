# WWCP_OPCP

A C# / .NET 10 implementation of Hubject's Open Plug&Charge Protocol (OPCP) 1.0.0 — clients *and*
servers for all six components (RCP, PCP, CPS, CCP, EST, Webhooks) plus the OAuth2 token endpoint.

## Orientation

- `docs/implementation-plan.md` — the plan being executed, including the per-phase order, the
  spec-defect decisions (§5.4) and the testing strategy. Read it before adding a component.
- `libs/OPCP/OPCP-1.0.0/reference/*.json` — the normative OpenAPI documents. Eight of them.
- `libs/OPCP/OPCP-1.0.0/docs/` — the narrative half: `04_authentication.md` carries the roles and
  rights matrix, `05_handling-of-ids.md` the identifier grammars, `components/` one file per service.
- `README.md` — what OPCP is and how the components relate.

## Build & test

```bash
dotnet build WWCP_OPCP.slnx
```

```bash
dotnet test WWCP_OPCP_Tests --filter "TestCategory!=LiveHubject"
```

Hermod and Styx are submodules and build from source; their own warnings are not ours to fix. Our
two projects compile clean, and `WWCP_OPCP_Tests` builds with `TreatWarningsAsErrors`.

## Ground rules

- **English everywhere** — code, comments, docs, commit messages.
- **Namespace `cloud.charging.open.protocols.opcp`**, sub-namespaces in PascalCase
  (`.DataStructures.Ids`, `.HTTP`, `.PKI`, `.Tests`). Assembly `WWCP_OPCP`.
- **The specification is read, never copied.** Test vectors lifted from its examples live in
  `WWCP_OPCP_Tests/Vectors/` with their source named; the spec is CC BY-SA 4.0, this repo is AGPL.
- **Parse leniently, emit strictly.** OPCP contradicts itself in a dozen documented places — enum
  casing, two ISO 15118-20 namespaces, `enabledEvents` vs `events`, three names for the webhook
  signature header. Accept every form the spec or its examples show; emit the current one. Each such
  concession belongs in the plan's table, with the file and line that motivates it.
- **House style, from WWCP_OCPI / WWCP_OCPP / WWCP_ISO15118**: identifiers as
  `readonly struct X : IId<X>`; wire vocabularies as PredefinedStrings structs, not enums; complex
  types with `TryParse(JObject, out T, out String? ErrorResponse, CustomJObjectParserDelegate<T>?)`
  and `ToJSON(CustomJObjectSerializerDelegate<T>?)` built on `JSONObject.Create`; `#region` blocks
  per property with `[mandatory]` / `[optional]`; a `#region Documentation` holding the schema
  fragment the type implements.
- **Tests**: NUnit with `Assert.That` only — never `ClassicAssert`. Method names read as sentences,
  `Words_separated_by_underscores`. Servers bind ephemeral ports (`IPPort.Zero`), never fixed ones.
  Anything touching the network outside loopback gets `[Category("LiveHubject")]`.
- **No new NuGet dependencies.** BouncyCastle 2.7.0 (already Hermod's) covers what .NET lacks:
  PKCS#10 creation, PKCS#7/CMS, OCSP, Ed448. Everything else is BCL or Hermod/Styx.
- **Reuse Hermod's PKI** (`libs/Hermod/Hermod/PKI/PKIFactory.cs`): key generation, CA issuance, CSR
  *signing*, chain validation, PEM export. It cannot create CSRs, speak PKCS#7 or OCSP — those are
  ours to write, in `WWCP_OPCP/PKI/`. Its `SubjectName` parameter is a bare common name, not a
  distinguished name: the factory builds `CN={SubjectName}` itself. It takes a *lifetime*, never a
  validity window, clamps a certificate to its issuer's `NotAfter`, and shifts both boundaries back
  by the local UTC offset (it converts an already-UTC `Timestamp.Now` as if it were local). Assert
  validity dates to the day, not to the second.

## Hermod HTTP, as it actually behaves

Four things about mounting an API cost a debugging round each. `AOPCPHTTPAPI` handles all of them;
follow it rather than rediscovering them.

- **One API per path.** Each OPCP service is its own `HTTPAPI` under its own mount path
  (`/v1/root/`, `/oauth/`, …). Two APIs at the same path throw at construction.
- **A mount path must end in a slash.** The server strips the mount path off a request *by length*
  and counts on that slash; without it the API sees `t/rootCerts` instead of `/rootCerts` and
  nothing matches. `AOPCPHTTPAPI` normalizes it.
- **Handler routes are relative to the mount path.** Use `Route("rootCerts")`, never
  `URLPathPrefix + "..."` — that only worked when the API sat at the root.
- **Path parameters are named.** Read them with `request.TryGetURLParameter("rootCertificateId")`.
  The positional `ParsedURLParameters` array still exists but the current server no longer fills it,
  so reading from it silently yields nothing.
