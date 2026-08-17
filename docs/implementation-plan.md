# WWCP OPCP — Implementation Plan

**Target:** A modern C# / .NET 10 implementation of Hubject's **Open Plug&Charge Protocol (OPCP) 1.0.0**
(spec submodule: [libs/OPCP](../libs/OPCP), commit `de066c8`, 2026-04-02), built on
**Vanaheimr Hermod** (HTTP) and **Styx/Illias** (JSON, ids, utilities), tested self-contained with **NUnit**.

---

## 1. Context

OPCP defines the REST interfaces of an ISO 15118 Plug&Charge ecosystem (Hubject's implementation of
VDE-AR-E 2802-100-1). It consists of **six components**, specified as OpenAPI 3.0.0 documents in
`libs/OPCP/OPCP-1.0.0/reference/` plus narrative markdown in `libs/OPCP/OPCP-1.0.0/docs/`:

| # | Component | Spec file | Purpose |
|---|-----------|-----------|---------|
| 1 | **RCP** — Root Certificate Pool | `rcp.v1.json` (v1.1) | Trust store for V2G / OEM / MO / PE root CA certificates |
| 2 | **PCP** — Provisioning Certificate Pool | `pcp.v1.json` | OEM provisioning certificates (+ Sub-CA chain) keyed by PCID |
| 3 | **CPS** — Certificate Provisioning Service | `cps.v1.json` | Signs (or generates + signs) contract data → `CertificateInstallationRes` |
| 4 | **CCP** — Contract Certificate Pool | `ccp.v1.json` | Stores signed contract data; serves the ISO 15118 hot path to CPOs/OEMs |
| 5 | **EST** — V2G PKI enrollment (RFC 7030) | `est.v1.json` | CSR-based leaf certificate issuance + CA chain download |
| 6 | **Webhooks** | `webhooks.v1.json`, `webhook.payload.v1.json` | Event subscription management + HMAC-signed callbacks |
| — | **OAuth2** token endpoint | `accessToken.v1.json` | Client-credentials → 24 h JWT bearer token |

We implement **both sides** of every interface:

* **Typed HTTP clients** — what an OEM / MO / CPO / CPS backend needs to talk to Hubject (or any other OPCP ecosystem).
* **HTTP server APIs** with in-memory stores — a complete, self-contained **reference ecosystem**. This is what
  makes the test suite independent of Hubject, and doubles as the seed of an *open* Plug&Charge pool implementation.

A full digest of the spec (all endpoints, schemas, defects) was produced during analysis; the authoritative
sources remain the files under `libs/OPCP/OPCP-1.0.0/`.

### Non-goals (for now)

* **No ISO 15118 EXI codec.** All ISO 15118 payloads in OPCP (`certificateInstallationReq/Res`, `signedData`)
  are opaque base64 blobs on the wire. We keep them opaque and provide **pluggable seams** (see §5.6) so the
  real EXI/XMLDSig machinery from `WWCP_ISO15118` can be plugged in later — if needed, add it as another
  submodule: `git submodule add https://github.com/OpenChargingCloud/WWCP_ISO15118.git libs/WWCP_ISO15118`.
* No persistence backends (in-memory stores behind interfaces first).
* No live Hubject conformance testing in CI (optional `[Explicit]`/category-gated smoke tests only).

---

## 2. Repository & solution layout

```
WWCP_OPCP/
├── WWCP_OPCP.slnx                     # new-style solution: WWCP_OPCP, WWCP_OPCP_Tests,
│                                      #   libs/Hermod/Hermod/Hermod.csproj, libs/Styx/Styx/Styx.csproj
├── LICENSE                            # AGPL-3.0 (house standard for WWCP protocol repos)
├── Contributor License Agreement.txt
├── README.md                          # what OPCP is, layout table, build/test, "Your participation" boilerplate
├── SECURITY.md
├── CLAUDE.md                          # orientation, build & test commands, ground rules
├── .gitignore
├── libs/                              # existing submodules: OPCP (spec), Hermod, Styx
├── docs/
│   └── implementation-plan.md         # this file
├── WWCP_OPCP/                         # main library
└── WWCP_OPCP_Tests/                   # NUnit test project
```

### Project settings

**`WWCP_OPCP/WWCP_OPCP.csproj`**

```xml
<TargetFramework>net10.0</TargetFramework>
<LangVersion>preview</LangVersion>
<Nullable>enable</Nullable>
<ImplicitUsings>enable</ImplicitUsings>
<RootNamespace>cloud.charging.open.protocols.opcp</RootNamespace>
<AssemblyName>WWCP_OPCP</AssemblyName>
```

* `<ProjectReference Include="..\libs\Hermod\Hermod\Hermod.csproj" />`
* `<ProjectReference Include="..\libs\Styx\Styx\Styx.csproj" />`
  (Hermod already references Styx as `..\..\Styx\Styx\Styx.csproj` — resolves in this layout, nothing to patch)
* `<PackageReference Include="BouncyCastle.Cryptography" Version="2.7.0" />` (direct use in the PKI layer;
  same version as Hermod/Styx). Newtonsoft.Json 13.0.4 comes transitively — no direct reference needed.

**`WWCP_OPCP_Tests/WWCP_OPCP_Tests.csproj`**

```xml
<IsPackable>false</IsPackable>
<TreatWarningsAsErrors>true</TreatWarningsAsErrors>
```

* NUnit **4.6.1**, NUnit3TestAdapter **6.2.0**, Microsoft.NET.Test.Sdk **18.8.1**,
  NUnit.Analyzers **4.3.0** (`PrivateAssets=all`), `<Using Include="NUnit.Framework" />`
* Test vectors: `<None Include="Vectors\**\*.json" CopyToOutputDirectory="PreserveNewest" />`

### Conventions (house style)

* File header: AGPL header, `Copyright (c) 2026 GraphDefined GmbH`, *"This file is part of WWCP OPCP
  <https://github.com/OpenChargingCloud/WWCP_OPCP>"*.
* One type per file; block-scoped namespaces; usings grouped BCL → third-party → Vanaheimr → cloud.charging.
* Namespace: `cloud.charging.open.protocols.opcp` (lowercase protocol segment; no version suffix —
  OPCP has a single major version, and if a breaking v2 ever appears we split like OCPI did).
  Sub-namespaces stay PascalCase: `.DataStructures.Ids`, `.HTTP`, `.PKI`, `.Tests`.
* Ids as `readonly struct X : IId<X>` (template: `Location_Id` in WWCP_OCPI / `APIKey_Id` in Hermod).
* Closed string vocabularies as **PredefinedStrings** structs (template: OCPP v2.1 `CertificateStatus`),
  not C# enums — the spec's casing is inconsistent, so parsing is case-insensitive where the spec diverges.
* Complex types: class with `[Mandatory]`/`[Optional]` properties, `Parse`/`TryParse(JObject, out T,
  out String? ErrorResponse, CustomJObjectParserDelegate<T>?)`, `ToJSON(CustomJObjectSerializerDelegate<T>?…)`
  over `JSONObject.Create(...)`, `#region Documentation` containing the relevant OpenAPI schema fragment,
  `Clone()`, operators, `Equals`/`GetHashCode`/`ToString`. JSON helpers from Illias
  (`ParseMandatory`/`ParseOptional`…).
* Tests: `Assert.That` constraint style only (no `ClassicAssert`), `[TestFixture]`, abstract `A…Tests`
  base classes for infrastructure.

---

## 3. Main library structure

```
WWCP_OPCP/
├── DataStructures/
│   ├── Ids/                  EMA_Id, PCID, WMI, Provider_Id, EVSE_Id, SECC_Id,
│   │                         RootCertificate_Id, WebhookEndpoint_Id, Trace_Id, Session_Id
│   ├── PredefinedStrings/    RootCertificateType (MO|V2G|OEM|PE), SignatureAlgorithm
│   │                         (secp256r1|secp521r1|ed448), XSD_MsgDefNamespace, WebhookEventType,
│   │                         CA_Type (mo|cpo|oem|cps|veh, optional operator prefix),
│   │                         ISO_Version (ISO15118-2|ISO15118-20), WebhookEndpointStatus, OPCPRole
│   ├── Shared/               OPCPError (errorMessages[] + traceId — the one shared error type that
│   │                         rcp/pcp/ccp $ref from cps.v1.json), PnCCertificate (base64-DER
│   │                         wrapper, BouncyCastle parse → DN, CN, serial, SKI/AKI, validity,
│   │                         SHA-256/SHA-1 fingerprints, PEM export), Metadata
│   ├── RCP/                  RootCertificate (RootCertV2), AddRootCertificateRequest,
│   │                         GetAllRootCertsResponse, GetRootCertResponse, CertificateTrustList (stub)
│   ├── PCP/                  ProvisioningCertificate (request), ProvisioningCertificateData (response),
│   │                         GetProvisioningCertificateResponse
│   ├── CPS/                  ContractData (current flat), ContractSignatureCertChain + legacy
│   │                         contract-data (nested), SignedContractDataRequest/Response,
│   │                         CreateSignedContractDataRequest/Response (deprecated endpoints),
│   │                         GenerateSignedContractDataRequest, CpsSigner, GetAllCpsSignersResponse
│   ├── CCP/                  GetSignedContractDataRequest/Response (CCPResponse → emaidContent[] →
│   │                         messageDef), AddSignedContractDataRequest, ProvideContractDataResponse,
│   │                         LookupContractResponse, ContractInfo (XMLContracts entry, defaultContract)
│   ├── EST/                  (mostly binary — CSR/PKCS#7 types live in PKI/)
│   └── Webhooks/             WebhookEndpointRequest / -UpdateRequest / -Response (tolerant
│                             enabledEvents|events), WebhookEvent envelope, RootEventPayload,
│                             ContractEventPayload (webhook.payload.v1.json)
├── Auth/                     AccessTokenRequest/Response, IAccessTokenProvider
│                             (StaticTokenProvider, ClientCredentialsTokenProvider with expiry-aware
│                             caching + auto-refresh), IAccessTokenValidator, TestTokenIssuer
│                             (hand-rolled HS256 JWS — no extra NuGet), OPCPTokenInfo (roles, WMI
│                             whitelist, provider-id whitelist — Hubject's namespaced claims),
│                             role/rights enforcement helpers per docs/04_authentication.md
├── HTTP/
│   ├── OPCPEndpointConfig    region ∙ stage ∙ domain → base URL (`https://{region}.{stage}.{domain}`);
│   │                         constants for Hubject eu/us × test/qa/prod; fully overridable (specs
│   │                         have empty `servers`)
│   ├── AOPCPHTTPClient       : AHTTPClient — bearer-token injection, OPCPError parsing, traceId
│   │                         propagation, custom-header support, request/response log events
│   ├── AccessTokenClient     POST /oauth/token
│   ├── RCP_HTTPClient, PCP_HTTPClient, CPS_HTTPClient, CCP_HTTPClient,
│   │   EST_HTTPClient, Webhooks_HTTPClient
│   ├── RCP_HTTPAPI, PCP_HTTPAPI, CPS_HTTPAPI, CCP_HTTPAPI, EST_HTTPAPI,
│   │   Webhooks_HTTPAPI      server side, mountable on a shared Hermod HTTPAPI/HTTPServer
│   ├── WebhookReceiver_HTTPAPI   partner-side callback endpoint: HMAC validation (constant-time,
│   │                         accepts X-Hubject-Signature / payload-signature / X-Operator-Signature),
│   │                         raises .NET events per event type
│   ├── WebhookDeliveryService    dispatches ecosystem events to registered endpoints, signs payloads,
│   │                         retry policy (spec: 3 × 1 h on 5xx — intervals configurable for tests)
│   └── OPCPTestEcosystem     composition root: one HTTPServer + all six services + stores + token
│                             issuer + webhook dispatcher + test PKI — the heart of self-contained tests
├── IO/                       OPCPResponse<T> (HTTP metadata + parsed payload | OPCPError),
│                             OPCPHTTPHeaders (broadcast, alwaysReturnEXI, X-Skip-Revocation, …),
│                             content-type registration (application/pkcs10, application/pkcs7-mime,
│                             application/ocsp-request/-response — via Hermod's auto-registering
│                             HTTPContentType.TryParse)
├── PKI/                      see §5.5
└── Stores/                   IRootCertificateStore, IProvisioningCertificateStore, IContractDataStore,
                              ICpsSignerStore, IWebhookEndpointStore + InMemory* implementations,
                              domain-event hooks feeding the WebhookDeliveryService
```

---

## 4. Per-service behavior to implement

The endpoint surface (17 REST operations + EST + webhooks) with the semantics the **server APIs** must
honor and the **clients** must expose:

### RCP (`/v1/root`)
* `GET /rootCerts/{rootCertificateId}` (all roles), `GET /rootCerts?rootType=mo|v2g|oem`
  (filter parses case-insensitively — body enum is `MO|V2G|OEM|PE`), `PUT /rootCerts` (Admin),
  `DELETE /rootCerts/{id}` (Admin, fires events), `GET /ctl` (spec placeholder → types + stub).
* On PUT, the server derives all informative `RootCertV2` fields (DN, CN, serial, AKI base64+hex,
  validity, SHA-256/SHA-1 fingerprints) from the DER via the `Certificate` wrapper.

### PCP (`/v1/oem`)
* `PUT /provCerts` with the documented **validation pipeline in order**: ① PCID's WMI against the
  caller's WMI whitelist → ② shell-model validity (leaf→root all currently valid) → ③ OCSP/CRL status
  of every certificate → ④ chain up to an OEM root present in the RCP. First failure → specific 400.
* Re-PUT same PCID = overwrite; **key-pair change detection** (SPKI comparison) → cascade-delete all
  CCP contracts of that PCID + `mo.prov.cert.updated` event.
* `GET /provCerts/{pcid}` (re-checks OCSP + chain before delivery, `broadcast` header),
  `DELETE /provCerts/{pcid}` (cascades: CCP delete for all EMAIDs of the PCID, revocation hook,
  `mo.prov.cert.deleted`), `GET /provCerts/lookupVehicle/{pcid}` (200 without body / 404).

### CPS (`/v1/cps`, plus the un-prefixed `GET /cps/signer`)
* Current: `PUT /contractData/signed` (→ 201 `SignedContractDataResponse`; stores in CCP **iff** a valid
  `pcid` was supplied), `PUT /generate/signedContractData` (V2G-MO-CA path: CA issues the contract
  certificate itself from EMAID/PCID/validity, signs, stores in CCP; re-call replaces),
  `GET /cps/signer` (signer/V2G-root discovery).
* Deprecated but still operated by Hubject → implement too: `PUT /signedContractData` (sign only) and
  `PUT /forward/signedContractData` (sign + store), with the legacy nested `contract-data` shape
  (chain order: MO Sub-CA2 first, then Sub-CA1).

### CCP (`/v1/ccp`)
* **Hot path** `POST /signedContractData` (CPO): headers `alwaysReturnEXI` (default true) + `broadcast`;
  decodes `certificateInstallationReq` via the pluggable seam (§5.6), selects contract data matching the
  EV's advertised V2G roots; ISO 15118-2 semantics: return exactly **one** item — the default contract;
  **polymorphic 404** (plain `OPCPError` vs. ISO-compliant EXI `CCPResponse` when `alwaysReturnEXI`).
* `PUT /signedContractData` (CPS writes), `DELETE /signedContractData/{emaid}` (MO; `X-Skip-Revocation`
  header; revocation-before-delete rule for operator-issued contract certs),
  `GET /provideSignedContractData/{emaid}/{pcid}` (OEM; optional `sessionID` hex query),
  `POST /signedContractData/{pcid}/{emaid}/default` (default-contract rules: first contract is default;
  deleting the default selects **no** new default + notifies the OEM),
  `GET /lookupContract/{emaid}`, `GET /signedContractData/{pcid}`.

### EST
* `POST /.well-known/est/{ca}/simpleenroll/{iso-version}` — `application/pkcs10` (base64 CSR) in,
  `application/pkcs7-mime; smime-type=certs-only` (base64) out; CA types `mo|cpo|oem|cps|veh` with
  optional operator prefix; CSR **CN rules** enforced: PCID (oem/veh), EMAID (mo), EVSEID/SECCID (cpo).
* `GET /{ca}/cacerts/{iso-version}/{algorithm}/` — chain download per algorithm
  (secp256r1 | secp521r1 | ed448).

### Webhooks
* Management CRUD under `/v1/webhook/endpoints` (secret generation on create; `providerIds`/`wmis`
  scoping in responses; tolerant `enabledEvents`|`events` parsing).
* Delivery: HMAC-SHA256 hex over the **raw body**, `sha256=<hex>` header format, full 16-event catalogue
  (union of `webhooks.v1.json`, payload spec and docs — the spec enum alone is incomplete), retry 3×
  (interval configurable), cascade events wired from RCP/PCP/CCP store operations.

---

## 5. Cross-cutting design

### 5.1 Authentication
* Client side: `ClientCredentialsTokenProvider` calls `AccessTokenClient`, caches the JWT, refreshes
  before `expires_in` (24 h) elapses; `AOPCPHTTPClient` attaches `Authorization: Bearer …` via Hermod's
  `HTTPBearerAuthentication`. A `StaticTokenProvider` covers pre-issued tokens.
* Server side: `IAccessTokenValidator` abstraction. `TestTokenIssuer` issues/validates **hand-rolled
  HS256 JWTs** (base64url + HMACSHA256 — pure BCL, no new dependency) carrying Hubject-style namespaced
  claims: roles, allowed WMIs (OEM scoping), allowed CountryCode+ProviderID prefixes (MO scoping).
* Enforcement per the roles & rights matrix in `docs/04_authentication.md` — including the spec gaps:
  `PUT /v1/cps/contractData/signed` and the whole webhooks API declare no security → we enforce OAuth2
  like everywhere else.

### 5.2 Error handling & results
* One shared `OPCPError` (`errorMessages[]`, `traceId`) — resolves the cross-file `$ref`s.
* Clients return `OPCPResponse<T>`: HTTP status + runtime + traceId + either parsed payload or
  `OPCPError`; the CCP client additionally distinguishes the EXI-shaped 404.

### 5.3 Identifier handling (`docs/05_handling-of-ids.md`)
* `EMA_Id`: tolerant parse (optional separators, case-insensitive), normalized storage (uppercase, no
  separators, 14/15 chars), exposes `CountryCode`, `ProviderId` (first 5 = MO scope), `Instance`,
  optional check digit. Check-digit *computation* (DIN SPEC 91286-style) as optional validation.
* `PCID` (17–18 alnum) exposing `WMI` (first 3 = OEM scope); `EVSE_Id`/`SECC_Id` per the documented
  regexes; `RootCertificate_Id`/`Trace_Id` (UUID); `Session_Id` (hex, ≤ 8 bytes).

### 5.4 Spec-defect decisions (parse leniently, emit strictly)
| Defect | Decision |
|---|---|
| `rootType` casing differs (query `mo` vs body `MO`) | case-insensitive parse, canonical uppercase emit |
| Two ISO 15118-20 namespaces (`…20:2020` EST vs `…20:2022` RCP/webhooks) | both accepted, distinct `XSD_MsgDefNamespace` values |
| `enabledEvents` vs `events` in webhook responses | accept both, emit `enabledEvents` |
| `cpsV2GRootCertificateFingerprint` carries UUID regex (and is swapped with `cpsRootCertificateDN` in `LookupContractResponse`) | validate as 64-hex SHA-256, ignore the spec patterns |
| `RootCertV2.maxProperties: 1` | ignore (schema bug) |
| Webhook signature header name varies (3 names) | accept all three, emit `X-Hubject-Signature` + `payload-signature` |
| CCP 404 polymorphism | branch on payload shape, not status code |
| Legacy `priority` vs `defaultContract` | model `defaultContract`, tolerate `priority` on input |
| PCP rename notices (`subCA1Certificate`→`subCa1Certificate`, `vehicleCertificate`→`provisioningCertificate`) | accept both on parse, emit current spec names |
| AKI dual encoding (base64 vs hex-with-colons) | `PnCCertificate` exposes both |
| EMAID/PCID path patterns write the groups as `\w`, which admits underscores, while the narrative normalization rule is strictly alphanumeric | the stricter rule wins — an underscore is nothing ISO 15118 can carry |

### 5.5 PKI / crypto layer (BouncyCastle where .NET can't)
Reused from **Hermod `PKI/PKIFactory`** (already BC 2.7.0-based): EC/Ed448 key generation, root/intermediate
CA creation, **CSR signing**, chain validation (`ChainReport`), BC↔.NET certificate conversion, PEM export.

New in `WWCP_OPCP/PKI/` (all BouncyCastle — .NET has no public API for these):
* **`CSRBuilder`** — PKCS#10 creation (Hermod can only *sign* CSRs, not create them) with CN rules per CA type.
* **`Pkcs7CertificateContainer`** — certs-only CMS/PKCS#7 encode + decode (`CmsSignedData[Generator]`) for EST.
* **`OCSPClient` + `OCSPResponder_HTTPAPI`** — RFC 6960 request/response over `Org.BouncyCastle.Ocsp`,
  responder mounted as a Hermod API so the PCP validation pipeline is testable end-to-end (spec: OCSP
  is unauthenticated). CRL generation (`X509V2CrlGenerator`) + checking as the alternative path.
* **`PnCTestPKI`** — builds the complete ecosystem PKI in-process, per algorithm
  (`[TestCase]` over secp256r1 / secp521r1 / ed448): V2G Root → {CPO, CPS, MO} Sub-CA1 → Sub-CA2 →
  leaf (SECC / CPS signer / contract), OEM Root → OEM Sub-CAs → provisioning cert (PCID as CN),
  MO Root (own-PKI variant) → contract cert (EMAID as CN); plus "evil" variants for negative tests
  (expired, wrong CN, untrusted root, revoked) — conceptually mirroring `WWCP_ISO15118_PKIBuilder`,
  but standalone.
* **`ContractKeyCrypto`** — contract key pair generation, ECDH with the OEM provisioning certificate's
  public key, `contractSignatureEncryptedPrivateKey` encrypt/decrypt and `dHpublickey` handling per
  ISO 15118-2 semantics (AES-128-CBC session key; the 48-byte example in the spec matches), so CPS→CCP→OEM
  round trips are cryptographically real even without EXI.
* **`WebhookSignature`** — HMAC-SHA256 (pure BCL: `HMACSHA256` + constant-time compare).
* **Chain validation policy** — shell model validity, CN↔identifier match, root membership in RCP store.

### 5.6 ISO 15118 seams (keeping the EXI dependency out)
* `ICertificateInstallationReqDecoder` / `IContractDataSigner` abstractions in the CCP/CPS pipeline.
* Default **test implementations** use a deterministic, documented container format (JSON/XML in base64
  with a real ECDSA signature by the CPS signer certificate) — cryptographically verifiable in tests,
  explicitly **not** ISO 15118 wire format.
* A future `Iso15118ContractDataSigner`/`…ReqDecoder` backed by `WWCP_ISO15118` (EXI + XMLDSig) plugs in
  without touching the services — that's when the GitHub submodule gets added, not before.

---

## 6. Testing strategy (NUnit, self-contained)

Test project layout mirrors the library; abstract base `AOPCPTests` boots an `OPCPTestEcosystem`
(one Hermod `HTTPServer` on a **random loopback port** via `IPPort.Zero`, all six service APIs, fresh
`PnCTestPKI`, `TestTokenIssuer`, webhook dispatcher with second-scale retry intervals) in
`[OneTimeSetUp]`, tears it down in `[OneTimeTearDown]` — the pattern of Hermod's `AHTTPServerTests`
and OCPI's `ANodeTests`.

1. **Data-structure unit tests** — id parsing/normalization against every regex and tolerated form in
   `docs/05_handling-of-ids.md`; JSON round-trips (`ToJSON` → `TryParse` → equality) for every type;
   **golden vectors extracted from the spec examples** (`libs/OPCP/OPCP-1.0.0/reference/*.json`) stored
   under `Vectors/` with source attribution (spec is CC BY-SA 4.0); all lenient-parse cases from §5.4.
2. **Crypto unit tests** — `PnCTestPKI` build + `ChainReport` validation (good + every evil variant),
   CSR build→sign round trip, PKCS#7 encode/decode, OCSP request/response round trip (good/revoked/unknown),
   CRL, `ContractKeyCrypto` encrypt→decrypt round trip, webhook HMAC vectors (incl. the Go/Java example
   values from `docs/components/06_webhook-service.md`).
3. **Auth tests** — token endpoint round trip, expiry-aware caching/refresh, 401 on bad/expired token,
   403 on wrong role, WMI scoping (OEM may only touch own WMI), provider scoping (MO/EMAID).
4. **Per-service client↔server round trips** — for each of the 6 services: every operation, happy path +
   documented error paths (400 validation messages, 404, polymorphic EXI-404, custom headers
   `broadcast`/`alwaysReturnEXI`/`X-Skip-Revocation`, overwrite semantics, cascade effects on stores).
5. **End-to-end lifecycle test** — the full Plug&Charge story in one fixture:
   admin uploads roots → OEM enrolls via EST → OEM publishes provisioning cert to PCP (pipeline incl.
   OCSP passes) → MO looks up vehicle, fetches prov cert → CPS signs contract data (own-PKI path *and*
   generate path) → CCP stores it → CPO fetches via `certificateInstallationReq` → OEM fetches via
   `provideSignedContractData` and **decrypts the contract private key** → default-contract switch →
   PCP delete cascades CCP delete + revocation → the `WebhookReceiver_HTTPAPI` observed and
   HMAC-verified the exact expected event sequence.
6. **Optional live smoke tests** — category `LiveHubject`, `[Explicit]`, credentials from environment
   variables, excluded by default (like Hermod's `LiveDNS` filter).

CI (optional, mirroring `libs/Hermod/.github/workflows/ci.yml`): `dotnet test WWCP_OPCP_Tests` on
Windows + Linux + macOS, `--filter "TestCategory!=LiveHubject"`. Note: existing WWCP protocol repos ship
no CI — include it only if wanted.

---

## 7. Implementation phases

Each phase ends with a green `dotnet build WWCP_OPCP.slnx` + `dotnet test`.

| Phase | Content | Key deliverables |
|---|---|---|
| **0 — Scaffolding** | Repo files, `.slnx`, both `.csproj`s, header template, README/CLAUDE.md/LICENSE/.gitignore | solution builds, one placeholder test runs |
| **1 — Core** | Ids, PredefinedStrings, `OPCPError`, `Certificate` wrapper, `OPCPEndpointConfig`, `OPCPResponse<T>`, content-type registration; Auth: token client/provider/issuer/validator | unit tests layer 1 (ids/JSON) + 3 (auth) |
| **2 — RCP vertical slice** | RCP types, `RCP_HTTPClient`, `RCP_HTTPAPI`, `InMemoryRootCertificateStore` | establishes the pattern for all services; round-trip tests |
| **3 — PKI foundation** | `PnCTestPKI`, chain validation policy, `CSRBuilder`, OCSP client + responder, CRL | crypto test layer green; prerequisite for PCP |
| **4 — PCP** | Types, client, API with 4-step validation pipeline, overwrite/key-change/delete cascades (events as internal hooks first) | PCP round trips incl. OCSP-driven rejections |
| **5 — CPS + CCP** | Contract data types (current + legacy), `ContractKeyCrypto`, signer/decoder seams, CPS API (all 5 ops), CCP API (all 7 ops), default-contract semantics, polymorphic 404 | the contract-data core works end-to-end in-process |
| **6 — EST** | `Pkcs7CertificateContainer`, EST client + API, CN rules per CA | enroll → issued chain validates against test PKI |
| **7 — Webhooks** | Management CRUD, `WebhookDeliveryService` (HMAC, retries), `WebhookReceiver_HTTPAPI`, wire all cascade events from RCP/PCP/CCP | event sequences observable + verified in tests |
| **8 — E2E & polish** | Full lifecycle test, client loggers (`*_HTTPClientLogger`), README/docs, optional CI, optional `LiveHubject` smoke tests | complete self-contained test suite |

---

## 8. Verification

```bash
dotnet build WWCP_OPCP.slnx
```

```bash
dotnet test WWCP_OPCP_Tests --filter "TestCategory!=LiveHubject"
```

The suite is fully self-contained: loopback HTTP on random ports, generated PKI, no network, no Hubject
account needed. Optional: run the `LiveHubject` category against `plugncharge-test.hubject.com` with
`OPCP_CLIENT_ID`/`OPCP_CLIENT_SECRET` environment variables.

---

## 8a. Progress

**Phase 0 — done.** Repository, solution and both projects; `OPCPSpecification` recording the
implemented revision, guarded by `SpecificationDriftTests` reading the submodule on every run.

**Phase 1 — done**, with three adjustments made while building it:

* **Identifiers built:** `EMA_Id`, `PCID`, `WMI`, `Provider_Id`, `RootCertificate_Id`, `Trace_Id`.
  `EVSE_Id` and `SECC_Id` moved to phase 6 and `Session_Id` to phase 5 — each is used by exactly one
  service, and their grammars are better pinned down beside the operation that validates them than
  guessed at now (`Session_Id` in particular: the specification says only "HEX" and its error text
  "maximum 8" does not say whether that counts bytes or characters).
* **`Certificate` renamed to `PnCCertificate`.** Illias already publishes a static
  `org.GraphDefined.Vanaheimr.Illias.Certificate`; a second type of that name would be ambiguous
  for any consumer importing both namespaces.
* **The token layer is complete except its HTTP fetch.** `ClientCredentialsTokenProvider` owns the
  caching and renewal — the part worth testing on its own — and takes *how* to obtain a token as a
  delegate. `AccessTokenClient` and the `AOPCPHTTPClient` base class it needs are built in phase 2
  alongside the RCP slice, where they get their first real endpoint to talk to rather than being
  written against nothing.

Certificates are parsed through BouncyCastle rather than `X509Certificate2` throughout: OPCP admits
Ed448, and whether a platform certificate store loads one is a platform question this library should
not be asking.

**Phase 2 — done.** The HTTP layer and the Root Certificate Pool, both ends, over a real socket.

* `AOPCPHTTPClient` and `AOPCPHTTPAPI` carry everything the six services share: bearer tokens, the
  JSON request pipeline, the specification's error shape, role enforcement. `RCP_HTTPClient` and
  `RCP_HTTPAPI` are the first pair built on them and the template for the rest.
* `AccessToken_HTTPAPI` was added beyond the plan. Without it the ecosystem could verify a token but
  not issue one, so `AccessTokenClient` — built here after being deferred from phase 1 — had nothing
  to talk to. The ecosystem now authenticates end to end in-process.
* **`RootCertificate` stores only what is not in the certificate**: the pool's identification, the
  trust domain, and a few pointers the operator was handed. The distinguished name, common name,
  organization, serial, both key-identifier encodings, validity, both fingerprints and the curve are
  all derived, so no entry can describe itself incorrectly.
* Four undocumented Hermod behaviours around mounting an API are recorded in `CLAUDE.md` — one API
  per path, mount paths ending in a slash, routes relative to the mount, named path parameters.
  `AOPCPHTTPAPI` absorbs all four.
* The client reads OAuth2's `{error, error_description}` as well as the OPCP error shape: the token
  endpoint is an OAuth2 endpoint before it is an OPCP one.

**Phase 3 — done**, except CRLs.

* `PnCTestPKI` builds all three hierarchies ISO 15118 needs — a V2G root over the charging
  infrastructure, contract signing and operators without a PKI of their own; an OEM root over what a
  vehicle is born with; and a root for an operator that brings its own — each Root → Sub-CA 1 →
  Sub-CA 2 → leaf, on any of the three curves. Plus a fourth root nobody trusts, for testing what
  happens when a certificate chains somewhere unexpected.
* `PnCChainValidator` implements the shell model, the trust-anchor check and the ISO 15118 rule that
  a leaf's common name *is* the identifier. It walks the path with BouncyCastle rather than the
  platform's chain engine, for the Ed448 reason and because certificates arrive in request bodies
  rather than in a certificate store. A matching issuer name is checked first as a cheap filter, but
  only the signature decides.
* `OCSPResponder`, `OCSPClient` and `OCSP_HTTPAPI` are RFC 6960, unauthenticated as the specification
  requires. Everything that can go wrong — unreachable responder, unsigned answer, answer about a
  different certificate — comes back as **Unknown, never as Good**. What to do about not knowing is
  the caller's decision; the pools refuse.
* `CSRBuilder` creates PKCS#10 requests, which Hermod cannot: it can only sign them.
* **CRLs are deferred.** OCSP covers what phase 4's validation pipeline needs, and the specification
  treats revocation lists as the alternative path ("if applicable"). They belong with whichever phase
  first meets a deployment that publishes one.

Two things about Hermod's certificate factory, learned by having tests fail on them: a certificate is
clamped to its issuer's validity (asking for a thirty-year leaf under a ten-year sub-CA gives a
ten-year leaf), and certificates are issued starting slightly in the past, so that a verifier whose
clock runs behind does not reject one that was just issued.

**Phase 4 — done.** The Provisioning Certificate Pool, both ends, with the validation the
specification prescribes.

* **The request says nothing about which vehicle.** The PUT body has no PCID field, because in
  ISO 15118 the PCID *is* the common name of the provisioning certificate. The pool reads it from the
  certificate rather than being told it, so the two can never disagree.
* **The four checks run in a different order than the specification lists them**, deliberately: the
  chain is validated first, then revocation along the path it established. This costs nothing and
  gains two things — a certificate that chains nowhere is refused for *that* rather than for an
  unanswerable revocation question, and each certificate can be asked about at its actual issuer,
  which is how RFC 6960 identifies one and impossible to get right before the path is known.
* **Not knowing is not the same as good.** A revocation check that could not be made refuses the
  publication rather than waving it through.
* Revocation is re-checked when a certificate is *handed out*, not only when it is published: an
  operator about to write a contract must not be given a certificate that stopped being usable in
  between.
* The delete and key-change cascades are internal events (`OnProvisioningCertificateDeleted`,
  `OnVehicleKeyChanged`) that phase 5's contract certificate pool will subscribe to.
* **The trust anchor does not travel.** The pool publishes what it worked out about the root — its
  distinguished name, serial and key identifier — and not the root itself, because the recipient is
  supposed to already have that from the root certificate pool. So those fields are derived
  server-side and read as plain values client-side.
* A test ecosystem needs **one OCSP responder per issuing authority**, not one per hierarchy: a
  responder signs as the CA it answers for, and an asker verifies against that CA.

**Phase 5 — done: contract data, the Contract Certificate Pool and the Certificate Provisioning
Service.**

* `ContractData` reads and writes both shapes the specification carries: the current flat one and
  the nested `contractSignatureCertChain` the two deprecated operations still take.
* `ContractKeyCrypto` wraps a contract's private key against the vehicle's provisioning certificate
  by ephemeral ECDH, so the key crosses a charging station that cannot read it. **The shape is
  ISO 15118's — ephemeral ECDH, AES-128-CBC, a 16-byte IV in front — and the derivation of the
  session key from the agreed secret is this library's own.** Nothing in OPCP looks inside these
  bytes, so nothing here needs ISO's; a real vehicle does, and it arrives with the codec.
* **`IContractDataCodec` is the seam.** OPCP moves three ISO 15118 structures it never opens - the
  request a car makes, the response that goes back, and the signed contract data in between.
  `TestContractDataCodec` implements the seam with a container that is cryptographically real
  (genuine ECDSA, verified) and deliberately not the ISO wire format; every structure it makes says
  so in a `_format` property. Implementing this interface over WWCP_ISO15118 is the whole of what
  real EXI support would require.
* The **polymorphic 404** works as the specification intends: no contract yields HTTP 404 whose body
  is nevertheless a valid ISO response, because the charging station relaying it speaks ISO 15118
  and not HTTP. `alwaysReturnEXI: false` gets the plain refusal instead.
* **Default-contract rules**: the first contract filed for a vehicle is its default; deleting the
  default promotes nothing and raises `OnDefaultContractLost`, because choosing what a car charges
  under is not the pool's decision.
* The phase 4 cascades have their receiver: `CCP_HTTPAPI.AttachTo(pcp)` drops a vehicle's contracts
  when its provisioning certificate is depublished or its key changes.
* **The specification's CCP paths are ambiguous as a route tree**: `signedContractData/{emaid}`
  (DELETE), `signedContractData/{pcid}` (GET) and `signedContractData/{pcid}/{emaid}/default` (POST)
  put two different parameter names at one segment. They share one name internally and each handler
  reads it as what its own operation means; the wire paths are unchanged.

The Certificate Provisioning Service, the other half of this phase:

* **Signing joined the seam.** `IContractDataCodec.SignContractData` is the one method on it that
  produces an ISO 15118 structure rather than reading one, and it is the reason the pool accepts
  anything at all - the pool takes contract data only from a signer it trusts, and a vehicle
  verifies that same signature before installing the contract.
* **One request type for the current operation and both deprecated ones.** They carry the same
  fields and differ in which they insist on and in whether the contract data is nested; each
  handler enforces its own requirements. The PCID decides what *happens* to the result rather than
  what it looks like: with one, the signed contract is also filed in the contract certificate pool;
  without one, the operator files it itself.
* **`generate` is the only place where all three pools meet.** The vehicle comes from the
  provisioning certificate pool, the contract certificate is issued under the V2G mobility operator
  authority, its private key is wrapped against the key in the car's own certificate, the signature
  is anchored in a root from the root certificate pool, and the result goes into the contract
  certificate pool - from where that car collects it the next time it plugs in.
* **The certificate factory takes a lifetime, not a window.** A generated contract certificate
  therefore expires with the contract but *starts* at issuance rather than at `contractBegins`, and
  both boundaries are shifted by the local UTC offset because Hermod's factory converts an already
  UTC timestamp as if it were local. `ContractCertificateIssuerDelegate` is the seam for a
  deployment that has to honour an exact window - which is what one signing in an HSM would supply
  anyway; `CPS_HTTPAPI.IssuedBy(ca)` is the default for everyone else.
* **The service checks the chain it is asked to sign**, against MO and V2G anchors from the root
  certificate pool, when it is given one. Optional in the same sense as the provisioning pool's
  revocation check: an escape hatch for a development ecosystem and a hole anywhere else, because a
  signature from this service is the whole reason a contract is later believed.
* **`GET /cps/signer` really is un-prefixed** where everything else is under `/v1/cps`. Since routes
  are relative to a mount and cannot reach above it, the discovery gets a second mount of its own -
  and is served at `/v1/cps/signer` too, because a caller that assumes the prefix is not wrong.
* The published signer description **has nowhere to put a private key**, which is why the store
  holds `IssuedCertificate` and the wire type is derived from it on the way out. Its schema and its
  own example disagree about three field names (`cpsRootCertificateId`, `cpsCa1Certificate`,
  `cpsCa2Certificate` against `cpsV2GRootCertificateFingerprint`, `cpsSubCa1Certificate`,
  `cpsSubCa2Certificate`); all six are read, the schema's three are written.
* **Naming a root the service cannot sign under is refused rather than quietly answered**: an
  operator that names one is saying which of its cars have to be able to verify the result, and
  signing under another root would produce contract data those cars reject.
* The rights matrix is enforced where the interface document is silent: `contractData/signed`
  declares no security at all, and the matrix beside it gives it to operators with their own PKI.
  The two paths stay separate - an operator without a PKI of its own cannot use the signing path,
  and one with a PKI cannot use the generating path.

## 9. Decisions taken (overridable)

1. **Namespace `cloud.charging.open.protocols.opcp`** (lowercase protocol segment, PascalCase sub-namespaces) without version suffix (single major version; split later if v2 breaks).
2. **Server emulators live in the main library**, not the test project — they are reference implementations of an open PnC ecosystem, not test doubles.
3. **Deprecated CPS endpoints are implemented** (client + server) — Hubject still operates them.
4. **No ISO 15118 submodule now**; opaque payloads + seams (§5.6). Add `WWCP_ISO15118` from GitHub only when real EXI is needed.
5. **No new NuGet dependencies** beyond BouncyCastle 2.7.0 (JWTs hand-rolled, HMAC/AES/ECDH via BCL where possible, BC where .NET lacks: Ed448, PKCS#10 creation, PKCS#7/CMS, OCSP, X.509 building).
6. **`GET /v1/root/ctl`** implemented as typed stub (spec marks it "to be aligned by stakeholders").
