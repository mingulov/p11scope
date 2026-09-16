#!/bin/sh

library=$1

P11SCOPE_PREPARED_PYTHON=source-sentinel
export P11SCOPE_PREPARED_PYTHON
before_pwd=$PWD
before_umask=$(umask)
before_options=$-
before_traps=$(trap)

. "$library"

after_traps=$(trap)
if [ "$before_pwd" = "$PWD" ] && \
    [ "$before_umask" = "$(umask)" ] && \
    [ "$before_options" = "$-" ] && \
    [ "$before_traps" = "$after_traps" ]; then
    printf 'state=same\n'
else
    printf 'state=changed\n'
fi
printf 'python=%s\n' "${P11SCOPE_PREPARED_PYTHON-unset}"
