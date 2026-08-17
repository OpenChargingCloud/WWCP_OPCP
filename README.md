# WWCP OPCP

A C# / .NET 10 implementation of [Hubject's Open Plug&Charge Protocol
(OPCP)](https://github.com/hubject/opcp) — the set of REST interfaces that carry ISO 15118
Plug&Charge certificates between the parties of an e-mobility ecosystem: vehicle manufacturers,
e-mobility providers, charge point operators and the certificate pools between them.

This is a library, not a product. It gives you **both ends of every interface**: typed HTTP clients
for talking to an OPCP ecosystem, and HTTP server APIs implementing one. The servers exist because a
protocol you can only speak to somebody else's deployment is a protocol you cannot test — with both
ends in the box, the whole Plug&Charge lifecycle runs on a loopback socket, against a PKI generated
in-process, with no account anywhere. They are also, deliberately, the beginning of an *open*
Plug&Charge ecosystem rather than only a client for a closed one.


### What OPCP covers

Six components, specified as OpenAPI documents in the `libs/OPCP` submodule:

| Component | What it holds | Who writes | Who reads |
|---|---|---|---|
| **RCP** — Root Certificate Pool | V2G, OEM, MO and PE root CA certificates | ecosystem admin | everybody |
| **PCP** — Provisioning Certificate Pool | one OEM provisioning certificate per vehicle, keyed by PCID | OEM | MO, CPS |
| **CPS** — Certificate Provisioning Service | signs contract data into an ISO 15118 `CertificateInstallationRes` | — | MO |
| **CCP** — Contract Certificate Pool | signed contract data per PCID and EMAID | CPS | CPO, OEM |
| **EST** — RFC 7030 enrollment | issues the V2G PKI's leaf certificates from a CSR | — | CPO, MO, OEM, CPS |
| **Webhooks** | change notifications, HMAC-signed | ecosystem | everybody |

plus an OAuth2 client-credentials token endpoint, which is how every one of them is authenticated.

The certificates that flow through these pools are what let a car authenticate itself by plugging in
a cable. ISO 15118 defines that conversation between vehicle and charging station; OPCP is how the
certificates it needs get to the station in the first place.


### Layout

```
WWCP_OPCP/            the library: data structures, HTTP clients, HTTP APIs, PKI
WWCP_OPCP_Tests/      NUnit tests, including a full in-process ecosystem
docs/                 implementation plan
libs/OPCP             the specification, as a submodule — read, never vendored
libs/Hermod           HTTP client/server stack, TLS, and its BouncyCastle PKI factory
libs/Styx             Illias: JSON, identifiers, the parse/serialize idiom
```

The specification is a submodule rather than a copy, and a test reads it on every run: OPCP ships no
changelog and no git tags, so a moved submodule pointer is the only signal that the text changed.
`SpecificationDriftTests` turns that signal into a failing build naming the document that moved.


### Build & test

```bash
git submodule update --init --recursive
```

```bash
dotnet build WWCP_OPCP.slnx
```

```bash
dotnet test WWCP_OPCP_Tests --filter "TestCategory!=LiveHubject"
```

The suite is self-contained: loopback HTTP on ephemeral ports, a PKI minted per fixture, no network.
The `LiveHubject` category is the exception — those tests talk to a real ecosystem and read
`OPCP_BASE_URL`, `OPCP_CLIENT_ID` and `OPCP_CLIENT_SECRET` from the environment; they are excluded by
default and marked `[Explicit]` on top of that.

`PlugAndChargeLifecycleTests` is the one to read first. It runs the whole story through all six
services at once: three roots admitted, a vehicle certificate enrolled through EST and published to
the PCP, a contract signed by the CPS through both of its paths, a car plugging in at a charging
station, the manufacturer collecting the same contract and **decrypting its private key with the key
it generated before any of it started**, a default-contract switch, and finally a car that is sold —
taking its contracts with it, with a partner backend having heard and HMAC-verified every step.


### Using it

Talking to an ecosystem:

```csharp
var config  = new OPCPEndpointConfig(URL.Parse("https://open.plugncharge-test.hubject.com"));
var tokens  = AccessTokenClient.CreateTokenProvider(config, clientId, clientSecret);

var roots   = await new RCP_HTTPClient(config, tokens).GetAllRootCerts(RootCertificateType.V2G);
```

Running one — each service is a Hermod `HTTPAPI` on a shared server, at its own mount path:

```csharp
var server  = await HTTPServer.StartNew(IPPort.Parse(8080));

var rcp     = new RCP_HTTPAPI(server, AccessTokenValidator: validator);
var pcp     = new PCP_HTTPAPI(server, rcp.Store, AccessTokenValidator: validator);
var ccp     = new CCP_HTTPAPI(server, AccessTokenValidator: validator);

ccp.AttachTo(pcp);   // a vehicle that loses its certificate loses its contracts
```

An `OPCPClientLogger` can be attached to any client. It elides bearer tokens, signing secrets and
the OAuth2 client secret before anything is written, and leaves bodies out entirely unless asked.


### Scope

The ISO 15118 payloads OPCP carries — `CertificateInstallationReq` / `-Res` and the signed contract
data — travel as opaque base64 on the wire, and this library treats them that way, behind interfaces
that a real EXI and XMLDSig implementation can be plugged into. That implementation exists, as
[WWCP_ISO15118](https://github.com/OpenChargingCloud/WWCP_ISO15118); it is not a dependency here,
because nothing in OPCP itself needs to look inside those blobs.

Currently not in scope:
 - persistence — the pools keep their state in memory, behind store interfaces
 - the organizational half of the specification: how a root certificate is delivered out of band,
   verified by fingerprint over a second channel, and admitted by an operator


### Your participation

This software is free and Open Source under [GNU Affero General Public License (AGPL)](LICENSE).
We appreciate your participation in this ongoing project, and your help to
improve it and the e-mobility ICT in general. If you find bugs, want to request
a feature or send us a pull request, feel free to use the normal GitHub
features to do so. For this please read the Contributor License Agreement
carefully and send us a signed copy or use a similar free and open license.
