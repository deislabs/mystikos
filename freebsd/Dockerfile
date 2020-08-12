# Copyright Microsoft.
# Licensed under the attached Microsoft Software License Terms

FROM auchida/freebsd:latest

ARG UID
ARG GID

USER root

ENV PS1="\[\033[31;40;1m\][\u@\h]\[\033[32;40;1m\] \W\[\033[33;40;1m\]>\[\033[0m\]"

# Start from a Bash prompt
CMD ["/bin/sh"]
