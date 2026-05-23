# Tesherra Strategy

This document holds longer-arc strategic thinking, product positioning, and forward direction that sit one level above the architecture spec. Where `docs/ARCHITECTURE.md` says "what we build and how it works," this document says "where this is going and why it matters." Architecture is the ground truth for the system. Strategy is the ground truth for *why we are building it this way*.

## 1. Vision: the agentic layer as the next internet

The agentic layer — A2A as transport, agents as the new addressable principals — is becoming what TCP/IP and HTTP were to the previous era. New economies, new infrastructure, and new categories of work will be built on this layer. The platforms that own the trust and identity primitives for this new layer will look back on this moment the way Plaid, Stripe, and DocuSign look back on the early commercial web: boring infrastructure that captured enormous value because everything had to route through it.

Tesherra is one of those primitives.

## 2. The reframe: Delegations are the agent-era unit of application

**Application : Delegation.** In the pre-agent web, the unit was an Application — a monolith bundling data, logic, UI, and integrations behind a fixed interface that the user navigates *to* and *operates*. In the agentic web, the unit is a **Delegation** — a published package that the user *grants authority to* for a domain of their life, and which then operates on the user's behalf through their butler. The verb shifts from *operating* to *delegating*. The noun follows the verb.

A Delegation contains:

- **One or more Object class definitions** (Schemas — what the Objects in this domain look like)
- **Agent code** (domain agents — how the package manipulates, negotiates, and promotes Objects in its domain)
- **Policy templates** (sensible defaults for permission and scope)
- Optionally, **a renderer / UI**

The user does not navigate to a calendar app. The user has *granted a Delegation for scheduling*, and their butler routes calendar-related intents to the scheduling agent that Delegation installed. Same for Contract, Receipt, Health Record, Procurement Order. Each "application" in the legacy sense becomes a published Delegation in the new one.

This is not a future redesign. It is a *frame* for what the architecture is already doing.

## 3. Tesherra as substrate, marketplace, or both

The architecture (section 13.11) already has the technical primitive for a marketplace: the Schema Registry. It is currently scoped to schema definitions, but the logical extension is straightforward:

```
Schema Registry (today)              →    Delegation Registry (marketplace version)
─────────────────────────                  ──────────────────────────────────
JSON schema                                Full Delegation bundle:
Publisher signature                          - One or more JSON schemas
                                            - Publisher signature (verified principal)
                                            - Reference agent implementation
                                            - Policy templates
                                            - UI manifest (pointer, not hosted)
                                            - Version compatibility metadata
                                            - Dependency declarations
                                            - Distribution metadata (pricing, license, support)
```

The strategic question is whether to lean into the marketplace dimension or stay narrowly the trust layer. Both are real businesses; one is much larger.

## 4. Three time horizons

**Short term (v0 – v1, the first year or two).** Tesherra is the trust layer on top of A2A. MeshyCal is the first consumer and the test rig. Schema Registry exists in service of policy enforcement and provenance hashing. We do not market the marketplace dimension; we do not necessarily say it out loud to customers. The business is: be the verify-scope-attest layer for cross-boundary agent interaction.

**Medium term (v1 – v2, the next couple of years).** Tesherra-the-trust-layer becomes Tesherra-the-trust-layer-plus-Delegation-Registry. We publish a small number of Delegations ourselves (Calendar/Scheduling, Contract Negotiation, Procurement) as canonical examples and to seed real consumer behavior. The registry hosts our own Delegations plus a handful of trusted partner Delegations. Network effects begin: every new Delegation makes the substrate more valuable to existing users with butlers, which makes the substrate more attractive to new Delegation publishers.

**Long term (v2+, three or more years).** The Delegation Registry opens to third-party publishers. Now Tesherra is the substrate for the agentic web's distribution layer: any developer can publish a Delegation, the registry hosts the signed bundle, and users (via their butlers) can grant new Delegations the way they used to install apps. Tesherra captures value as both the trust layer (per-transaction) and the marketplace (distribution, ranking, search, verification badges). This is the largest version of the business and the version that justifies the architecture commitments we made at v0.

## 5. What this means for MeshyCal

Under the substrate-only frame, MeshyCal is the "first consumer." Under the marketplace frame, MeshyCal is something more specific:

**MeshyCal is the first published Delegation, used to seed the marketplace and prove the Delegation model works.**

That reframe sharpens the role: MeshyCal is not trying to be a standalone scheduling product competing with Calendly. It is a reference implementation of the Delegation pattern, optimized to demonstrate that:

1. A non-trivial Delegation — covering multiple Object classes (Calendar, Meeting, Proposal) plus agent code, policy templates, and UI — can be published, distributed, and adopted via Tesherra.
2. Users with butler agents can grant a Delegation and then interact across boundaries fluidly without operating an application directly.
3. The trust layer pays its keep (privacy-preserving negotiation, verifiable agreements).

MeshyCal succeeds strategically not when it has a million users but when it makes the *second* Delegation feel obvious to build.

## 6. Why this is not in ARCHITECTURE.md

The architecture spec describes decided commitments. The marketplace direction is a strategic *possibility* enabled by the architecture; it is not a current commitment. Mixing the two would either:

- Pollute the architecture with speculation ("we *might* extend the Schema Registry to..."), or
- Lock in marketplace commitments we have not earned yet.

This document holds the strategy. ARCHITECTURE.md holds the system. The Schema Registry exists in the architecture as a trust primitive; the marketplace possibility exists in strategy as a direction. The two stay separate until the marketplace direction becomes a build decision rather than a posture.

## 7. Open strategic questions

These are upstream of the architecture's open design questions (ARCHITECTURE.md section 14). They shape *what we are trying to build*, not how:

- **When does the marketplace dimension become a build commitment?** Probably triggered by either (a) a partner asking to publish on our registry, or (b) the second internal consumer making the bundling pattern obvious.
- **Do we publish MeshyCal as open source eventually?** Open-sourcing the first reference Delegation would make it easier for third parties to build their own. It might also commoditize MeshyCal itself. Tension worth carrying.
- **What is the value capture model?** Per-interaction fees (we are the toll booth), subscription on butler service, marketplace distribution cuts, enterprise verification tier. Each implies a different prioritization of what we harden first.
- **How do we avoid becoming the platform that gets disintermediated?** If we open the Delegation Registry too early, third parties may host their own and route around us. If we close it too late, we lose the marketplace position to a competitor that opens earlier.
- **When does the Delegation Authoring SDK emerge?** Today MeshyCal is hand-built against Tesherra's raw SDK. A reusable scaffolding layer for new Delegations (a `tesherra create-delegation` CLI, a base `Delegation` class, standard project structure, signing and registration helpers) is premature with only one example. It should emerge from comparing Delegation #1 and Delegation #2, identifying what is genuinely shared, and extracting that into a separate authoring SDK. Triggering condition: the second Delegation is committed to. Risk if too early: bad abstractions baked in and forced on future authors. Risk if too late: third-party Delegation authors hit too much friction to participate in the marketplace, slowing the network-effect curve in section 4.

## 8. Cross-references

- `docs/ARCHITECTURE.md` section 4.1, 8, 13.11: Schema Registry as currently defined
- `docs/ARCHITECTURE.md` section 10: First consumer (MeshyCal) and test-rig-vs-market framing
- `docs/ARCHITECTURE.md` section 14: Economic model open question, which interacts with this strategy
- `docs/DIAGRAMS.md`: visual reference for the trust layer that this strategy sits on top of
