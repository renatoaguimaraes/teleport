---
authors: Forrest Marshall (forrest@goteleport.com)
state: draft
---

# RFD 30 - Upgrade System

## What

System for automated/assisted upgrading of teleport installations.

## Why

Teleport, like virtually all software, must be periodically updated in order to
maintain security.  Outdated teleport isntallations also impose additional burdens
both on us, and our users.  Currently, teleport does not assist with its
own upgrade process, and does not inform users when the current installation is
in need of upgrading due to being too old, or due to the existence of a relevant
security patch.

By making teleport upgrades easier (or automatic), we can improve the experience
of using teleport, reduce workload for us and our users, and improve the security
of the teleport ecosystem at large.

## Intro

### High Level Goals

- The upgrade system must be *secure*.  In the worst-case, a compromised upgrade
system could allow an attacker to install arbitrary malicious software across the
teleport ecosystem. With this in mind, the upgrade system will be designed with
the aspirational goal of being resilient to compromise of any single machine,
secret, account, etc (in this context, "resilient" just means "won't result in
successful execution of a malicious installation").  In practice, this level of
fault-tolerance is essentially impossible to achieve, but compartmentalization
and redundancy will be primary guiding principals.

- The upgrade system must be *reliable*.  Specifically, the upgrade system must
be resilient to intermittent failures and self-healing to the greatest extent possible.
With this in mind, the upgrade system will embrace a kubernetes-esque model of enacting
change; components will continually attempt to reconcile the current state of the system
with some desired final state.  Care will also be taken to maximize cross-version and
cross-implementation compatibility.

- The upgrade system should be *modular* and *extensible*.  It should be easy to extend
the behavior of the upgrade system both as a user and as a maintainer.  The individual
components of the upgrade system must have simple and well-defined responsibilities.
It should be easy to write new components, and to hook into external systems.  Components
should also be highly opinionated about their domain of responsibility, while maintaining
as little opinion as possible about other domains (this extends to mundane things, e.g. we
will prefer purpose-specific validation and selection of defaults for resources, rather than
a monolithic `CheckAndSetDefaults` operation as is common in much of teleport's internals).

### Attack Scenarios

#### Malicious Distribution

**Scenario**: An attacker successfully leverages the upgrade system to directly distribute
malicious non-teleport software (or a malicious fork of teleport), causing existing teleport
clusters to install said malicious software on one or more servers (aka: the doomsday scenario).

We're going to roughly divide the possible avenues of attack into two families, direct and
indirect compromise.  In the case of direct compromise, the attacker successfully causes
"legitimate" distribution infrastructure to perform functions that result in the installation
of malicious software.  This may be via compromise of supply chain, software/libraries,
accounts, or even individuals. In the case of indirect compromise, the attacker successfully
tricks clients into believing that they are interacting with is, or that a package originated from,
some trusted source when that is not the case.  This may occur due to the compromise of a
cryptographic key or CA, manipulation of a client into using insecure protocols, redirection
of a client to an illigitimate download point, injection of malicious public key into a root
of trust, etc.

Direct compromise will be mitigated via compartmentalization.  In particular, we will divide
the sources of truth that clusters interact with into two abstract subsystems that can serve as
checks agianst one another.  The index/manifest subsystem will be the "discovery" point for new
teleport releases and their checksums, as well as metadata about the nature of the releases
(e.g. whether or not the release contains critical a critical security patch).  The
repository/distribution subsystem will be isolated from the index/manifest subsystem, and serve
as the origin from which releases can be downloaded and installed (actually, there are already
a number of distribution systems, but we may need some tweaks to meet all our requirements).
By keeping these two halves of the upgrade system isolated (separate code bases, secrets,
environments, etc) we can help compartmentalize security breaches.  Compromise of the index
cannot result in installation of unauthorized software if the repositories don't serve it.
Compromise of one or more repositories cannot result in the installation of unauthorized software
if the index does not publish matching checksums.

Indirect compromise will be partially mitigated by the split system described above, since the two
subsystems will rely on separate cryptographic identities.  For additional mitigation, we will also
require that compromise of any single store of trust (e.g. injection of a malicious TLS root cert)
or skipping of any single verification step (e.g. skipping package signature verification)
will not be sufficient to perform a compromised installation.  This is fairly straightforward, so
long as we rely on separate public keys/keystores for verifying package signatures and server
identities (most modern package managers already do this).


#### Malicious Downgrades

**Scenario**: Attacker successfully leverages the upgrade system to cause an outdated version of
teleport (presumably one with some vulnerability that the attacker would like to exploit) to be
installed.  This differs from the previous scenario in that the package has a valid signature and
was, at some point, considered a valid installation target.

Once again, we're going to subdivide this scenario into two families of attack: visible and masked
downgrades.  A visible downgrade is a downgrade where teleport "knows" that it is installing an older
version, but does so anyway.  This would most likely be caused by a compromised index/manifest system.
A masked downgrade is a downgrage that looks like an upgrade (i.e. teleport thinks it is installing
`v1.2.3` when it is actually installing `v0.1.2`).  This would most likely be caused by a compromised
distribution system.

The best way to prevent visible downgrades is to not allow downgrades! Unfortunately, this
may not be practical.  If the latest version turns out to have an unexpected issue, a downgrade may be
necessary.  The simplest solution (and the one we'll likely start with) is to require that downgrades
be triggered manually, but this isn't ideal.  A better solution would be to have custom policies for
downgrades, with a reasonable default being something like "previous patch release iff current release
was not a security patch".  Complementary to this would be including an ability to yank outdated/insecure
versions from distribution (or at least mark them as such).

Masked downgrades aren't a significant threat if only the distribution system is compromised, as the
index/manifest system will continue to provide checksums with correct versioning information.  Some
repository systems also resist tampering with version numbers, though not all do so.  That leaves us
with one final scenario: the index *and* at least one repository are compromised simultaneously (but
the compromise is not so severe as to put us in the previously discussed 'doomsday scenario').  This is
a bit niche, but lets exercise a little professional paranoia.  We should have a mechanism of validating
package version (prior to unpacking/installation) as part of package signature verification (i.e. on the
"distribution" side).  One appealing option is [minisign](https://jedisct1.github.io/minisign/) which
is a simple and modern signing utility that supports "trusted comments" (i.e. signed metadata) as part
of the signature file.


#### Compromised Build System

Out of scope for now, but I've heard all the cool kids are doing deterministic builds these days.


## Proposal

#### Overview

TODO

---

playing with some ideas, please ignore

---

```yaml
kind: version-control-directive
metadata:
  name: default
spec:
    # schedule constrains the *start time* of an upgrade (no guarantees are made
    # about when said upgrade completes, if it completes).
    schedule:
      not_before: '2021-04-29T00:00:00Z'
      time_range: '01:00:00-06:00:00'
      day_range: Mon-Fri

    # targets is the list of available installation targets.  targets are prioritized
    # by version.
    targets:
      - tags: [oss]
        version: '100.1.0-alpha.2'
        arch: amd64
        os: linux
        flavor: oss
        stable: false
        security_patch: false
        sums:
          rpm-blake2-256: '...'
          tgz-blake2-256: '...'
          deb-blake2-256: '...'
      - tags: [ent]
        version: '100.0.1'
        arch: amd64
        flavor: ent
        os: linux
        stable: true
        security_patch: true
        sums:
          rpm-blake2-256: '...'
          tgz-blake2-256: '...'
          deb-blake2-256: '...'
      - tags: [ent,fips]
        version: '100.0.1'
        arch: amd64
        os: linux
        flavor: ent
        stable: true
        security_patch: true
        sums:
          rpm-blake2-256: '...'
          tgz-blake2-256: '...'
          deb-blake2-256: '...'

    # installers describe mechanisms by which an installation target may be
    # applied to a server.  installation methods are prioritized by the target
    # versions that they match.  in the case that multiple installers match
    # a target, they are attempted in order until one succeeds.
    installers:
      - name: yummy-ent-installer
        kind: local-script
        target_selectors:
            - flavors: [ent]
        server_selectors:
            - name: Yummy servers
              server_roles: ['proxy','node']
              filter: 'contains(server.lables['pkg-manager'],'yum')
        env:
          TELEPORT_VER: '${target.version}'
          TELEPORT_SUM: '${target.sums["rpm-blake2-256"]}'
        install.sh: |
          #!/bin/bash
          set -euo pipefail

          tmp_dir=$(mktemp -d -t teleport-XXXXXX)

          yum install -y --downloadonly --destdir $tmp_dir teleport-ent-${TELEPORT_VER}

          package_file="$(ls $tmp_dir)"

          echo "$TELEPORT_SUM $tmp_dir/$package_file" | b2sum --check

          yum localinstall -y $tmp_dir/$package_file

      - name: curl-oss-installer
        kind: local-script
        target_selectors:
            - flavors: [oss]
        server_selectors:
            - name: Curly-whirly servers
              server_roles: ['proxy','node']
              filter: 'contains(server.lables['pkg-manager'],'kinda')'
            - name: Preview servers
              server_roles: ['proxy','node']
              permit_unstable: true
              filter: 'contains(server.lables['pkg-manager'],'kinda') && contains(server.labels['unstable-preview'],'yes')'
        env:
          TELEPORT_VER:  '${target.version}'
          TELEPORT_SUM:  '${target.sums["tgz-blake2-256"]}'
          TELEPORT_OS:   '${target.os}'
          TELEPORT_ARCH: '${target.arch}'
        install.sh: |
          #!/bin/bash
          set -euo pipefail

          tmp_dir=$(mktemp -d -t teleport-XXXXXX)

          pkg_name="teleport-v${TELEPORT_VER}-${TELEPORT_OS}-${TELEPORT_ARCH}-bin.tar.gz"

          cd $tmp_dir

          curl --tlsv1.3 -o $pkg_name "https://get.gravitational.com/${pkg_name}"

          echo "$TELEPORT_SUM $pkg_name" | b2sum --check

          tar -xf $pkg_name

          ./teleport/install

    # we're gonna be a little more agressive than usual where sync is concerned.
    internal: 
        nonce: 1
        written: '2021-04-29T00:00:00Z'
```
