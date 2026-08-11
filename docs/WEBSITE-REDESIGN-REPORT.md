# Agent Guard website redesign report

## Objective

Upgrade the existing Agent Guard site into a launch-quality product and documentation experience while preserving its technical fidelity, production route, certification intake, integrations, metadata, and open-source links.

## Before

The site already contained a sophisticated one-page technical presentation of Agent Identity, AGP, Edge, Runtime, deployment architecture, Cairo integration, certification, embedded documentation, and the open repository. Its dominant narrative began with generic security infrastructure and organized the experience around three product components. Documentation was browsable but not searchable, the certification form had no recoverable local draft, and the site did not yet include a dedicated threat narrative, ecosystem matrix, or FAQ.

## After

The redesigned journey is organized for both executive evaluation and technical implementation:

1. Identity-led launch promise and live authorization visualization.
2. Why-now threat model and independent-boundary design rule.
3. Five trust pillars with direct paths into the deeper system.
4. Identity, AGP policy, Edge, Runtime, architecture, and Cairo implementation detail.
5. Integration and ecosystem patterns with explicit maturity labels.
6. Evidence-based certification levels and durable application workflow.
7. Searchable embedded documentation and open-source adoption path.
8. Product-boundary FAQ and decisive integration/certification calls to action.

## Interaction and accessibility upgrades

- Semantic landmarks and heading hierarchy remain intact.
- Skip navigation, visible keyboard focus, reduced-motion behavior, accessible form labels, live form status, and native FAQ disclosure controls are preserved or added.
- Navigation now identifies the current section with `aria-current`.
- Documentation search is keyboard-native and reports available topic count.
- Certification application data survives recoverable navigation or request failures for the current tab and is removed after successful submission.
- Desktop, tablet, and mobile layouts receive explicit grid transitions without horizontal overflow.

## Fidelity and security decisions

No technical boundary was softened for marketing. Integration cards distinguish a reference integration, reference adapter, architecture pattern, and protocol profile. The certification application remains an intake for scoping and evidence review—not a conformance claim. The Edge managed-platform boundary, V0.1 HMAC limitation, proof-of-possession gap, signed approval limitation, non-bypassability requirement, and physical safety boundary remain visible.

## Deployment status

This redesign is prepared as a focused reviewable pull request. It is not directly deployed to production by this change set.

