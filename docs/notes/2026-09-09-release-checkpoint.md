<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Initial-release recovery checkpoint

This local checkpoint preserves the accumulated release source, native test
fixtures, test refactoring, documentation and dependency corrections. It is
a work-in-progress snapshot, not a release or a passing acceptance gate.

The previous complete artifact run recorded 96 passes and eight failures:
seven source-contract guards awaiting behavioral replacement, and one recorded
launcher handle-adoption failure whose original cause remains unknown. The
normal capture activation guard remains enabled while integration is finished.
A separately frozen diagnostic build passed the bounded original-root exit
regression on the supplementary host, with fresh profile and trace scenarios;
that result does not qualify the required kernel/ABI matrix or the public loops.
Some focused corrections still require independent review and final integrated
gates. Follow the architecture closure plan and ROADMAP for the remaining work.

The checkpoint includes the current local Aya package sources so their fixes
and tests have recoverable Git history. The selected next dependency direction
is pinned upstream crate inputs plus reviewable patch files applied by a
preparation step; its fresh-checkout build interface is being resolved.
Generated build products and runtime logs are excluded from Git.

Local source checkpoints must continue incrementally. Keep checkpoint history
and release qualification distinct; do not wait for the whole release to pass
before preserving a meaningful unit of work. Nothing is pushed, tagged or
published by this checkpoint.
