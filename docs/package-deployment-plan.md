<!-- snodec:begin page-header -->
<a id="banner"></a><a id="page-overview"></a>
<p><picture><source media="(max-width: 640px)" srcset="media/nav/banner-documentation-compact.svg"><img src="media/nav/banner-documentation.svg" alt="SNode.C IDP — Documentation" width="100%"></picture></p>
<p><a href="README.md#banner" title="Up to Documentation"><picture><source media="(prefers-color-scheme: dark)" srcset="media/nav/up-documentation-dark.svg"><img src="media/nav/up-documentation-light.svg" alt="Up to Documentation" title="Up to Documentation" width="160" height="28"></picture></a><a href="https://github.com/VolkerChristian#banner" title="Volker Christian account"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/account-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/account-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/account-dark.svg"><img align="right" src="media/nav/account-light.svg" alt="Volker Christian account" title="Volker Christian account"></picture></a><a href="https://github.com/SNodeC#banner" title="SNode.C organization"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/organization-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/organization-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/organization-dark.svg"><img align="right" src="media/nav/organization-light.svg" alt="SNode.C organization" title="SNode.C organization"></picture></a><a href="../README.md#banner" title="SNode.C IDP repository"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/repository-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/repository-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/repository-dark.svg"><img align="right" src="media/nav/repository-light.svg" alt="SNode.C IDP repository" title="SNode.C IDP repository"></picture></a><br clear="all"></p>
<!-- snodec:end page-header -->

# Package and deployment integration

This is the implementation and release checklist for packaging the IDP and its styled example application. No package workflow, publication or remote deployment is authorized by this checklist alone. The operator procedure is the [ten-step package deployment guide](package-deployment.md#banner), mirrored by the [interactive script](../scripts/deploy-core-snodec-org.sh).

## Responsibilities

The IDP repository owns the server, reusable authentication libraries, example client, CPack components and deployment command. DistributionPackages owns target selection, captured source revisions, dependency provenance, artifact validation, signing and publication. The SNodeC control repository owns canonical documentation navigation.

A product publication must preserve all other products in that target's package feed. The three-product pipeline must not assume a single counterpart. Dependency rebuilds must consume the exact published SNode.C packages that initiated them. MQTTSuite publication and OpenWrt support must remain intact.

Installation supplies software without opening a public listener. Deployment is an explicit operator action. Re-running deployment must preserve account data and cryptographic keys. Existing databases without their original signing or TOTP key must fail closed; deployment must never generate replacement keys for them.

## Package ownership

| Package | Responsibility |
| --- | --- |
| `snodec-idp` | Standalone server, service unit and deployment setup command |
| `snodec-idp-client-dev` | Client headers, static library and exported CMake package |
| `snodec-idp-server-dev` | Embeddable IDP library and its development dependencies |
| `snodec-idp-example` | Optional styled relying-party application and assets |

Native DEB/RPM targets use the existing distribution matrix. The deployment helper targets systemd hosts with managed Nginx or an existing proxy; Certbot is optional for Let’s Encrypt; OpenWrt deployment is outside this helper's scope. Package inventory must derive from CPack components, rather than a second hand-maintained package list.

## Deployment contract

The operator supplies the public IDP hostname, application hostname/callback registrations, optional hostname redirects and certificate ownership. Let’s Encrypt additionally requires an ACME contact email and acceptance of its terms. Google credentials and mail settings belong in a protected server-side configuration file. They must never enter workflow logs, repository files or command-line arguments.

Nginx terminates HTTPS and forwards the original Host and Origin to a loopback-only IDP. HTTP requests redirect to HTTPS, except for the ACME HTTP-01 challenge location. In Let’s Encrypt mode, Certbot owns certificate issuance and renewal; a deploy hook reloads Nginx after successful renewal. Existing PEM files and an operator-owned same-server proxy are alternative modes; their renewal remains operator-owned. All configured HTTPS redirect hostnames need certificate coverage too.

The setup command must validate input and existing web-server ownership before changing configuration. It must not replace unrelated Nginx sites. Configuration validation precedes reloads. Accounts, database files and private keys belong in persistent service-owned storage, outside package payloads. Removal of software does not remove account data.

The optional example is configured with the public IDP URL, its client ID, callback URL and the IDP public verification key. Its account/settings links must follow that configured IDP; private assets remain behind authentication.

## Verification and release gates

1. Build full and client-only configurations and external installed consumers.
2. Run offline authentication tests and package-content/dependency checks.
3. Test deployment validation, first provisioning, repeat provisioning and missing-key rejection on disposable fixtures.
4. Verify the styled client and authentication flow against disposable local services.
5. Run DistributionPackages tests for three-product capture, authenticated handoffs, sibling preservation and dependency dispatch.
6. Generate and audit canonical documentation navigation.
7. Review and merge the intended source and documentation changes. Keep publication a separate authorized action.
8. After separate authorization, build/publish and verify installation from the signed repository.
9. Only then deploy to the root server and verify real HTTPS, renewal, Google login, MFA, recovery mail and hostname routing.

Public deployment still requires the server OS/access, existing port 80/443 ownership, application hostname, redirect destinations, Google credentials and mail configuration. Local tests cannot establish that public DNS, ACME issuance or external Google/mail flows work.

## Implementation and deployment status

The styled client is now version-controlled under `examples/minimal-mfa-app`. CPack definitions, deployment helper and package workflow are implemented. The concrete operator procedure is in [Install and deploy the packaged IDP](package-deployment.md#banner). DistributionPackages owns project-specific installer selection, signed repository setup and publication; canonical navigation is maintained in the organization control repository. Certbot is not an IDP package dependency and is installed explicitly for the Let’s Encrypt workflow.

Local verification covers full/client-only builds, installed consumers, authentication tests, generated DEB/RPM contents, disposable deployment tests, Nginx syntax, HTTPS authentication flows and the styled example in Chromium. Check [published IDP target availability](https://github.com/SNodeC/Packages/blob/main/status/snodec-idp.md) before installation. A passing local check does not establish signed publication or successful root-server deployment. Installation from the signed repository, real ACME issuance/renewal, Google consent and external mail delivery must be verified for the selected deployment.
