#!/usr/bin/env bash
set -euxo pipefail

# curl -o endpoint 'https://relays.syncthing.net/endpoint'

# PORTS="$(jq -r '.relays[].url' endpoint | grep -Eo 'relay://[0-9:.]*' | sed 's#^relay://##' | awk -F: '{print $2}' | sort -n | uniq)"

function join_by { local d=$1; shift; local f=$1; shift; printf %s "$f" "${@/#/$d}"; }



NEWRULE="{"
QSTPROCESS="$(cat <<SELECTOR
      "process"          : "\/Applications\/QSyncthingTray.app\/Contents\/MacOS\/QSyncthingTray",
      "via"              : "\/usr\/local\/Cellar\/syncthing\/1.20.3\/bin\/syncthing"
SELECTOR
)"


################################################################################
# Predule
################################################################################
cat <<PRELUDE
{
  "description" : "",
  "name" : "test",
  "rules" : [
PRELUDE



################################################################################
# First: generic rules
################################################################################
cat <<RULE
    {
      "notes"            : "TCP based sync protocol traffic",
${QSTPROCESS},
      "direction"        : "incoming",
      "protocol"         : "tcp",
      "ports"            : "22000",
      "remote"           : "any",
      "action"           : "allow"
    }
  , {
      "notes"            : "TCP based sync protocol traffic",
${QSTPROCESS},
      "direction"        : "outgoing",
      "protocol"         : "tcp",
      "ports"            : "22000",
      "remote"           : "any",
      "action"           : "allow"
    }
  , {
      "notes"            : "QUIC based sync protocol traffic",
${QSTPROCESS},
      "direction"        : "incoming",
      "protocol"         : "udp",
      "ports"            : "22000",
      "remote"           : "any",
      "action"           : "allow"
    }
  , {
      "notes"            : "QUIC based sync protocol traffic",
${QSTPROCESS},
      "direction"        : "outgoing",
      "protocol"         : "udp",
      "ports"            : "22000",
      "remote"           : "any",
      "action"           : "allow"
    }
  , {
      "notes"            : "for discovery broadcasts on IPv4 and multicasts on IPv6",
${QSTPROCESS},
      "direction"        : "incoming",
      "protocol"         : "udp",
      "ports"            : "21027",
      "remote"           : "local-net",
      "action"           : "allow"
    }
  , {
      "notes"            : "for discovery broadcasts on IPv4 and multicasts on IPv6",
${QSTPROCESS},
      "direction"        : "outgoing",
      "protocol"         : "udp",
      "ports"            : "21027",
      "remote"           : "local-net",
      "action"           : "allow"
    }
  , {
      "notes"            : "stun servers :3478, from docs: https://docs.syncthing.net/users/config.html#config-option-options.stunserver",
${QSTPROCESS},
      "direction"        : "outgoing",
      "protocol"         : "udp",
      "ports"            : "3478",
      "remote-domains"   : [
        "stun.callwithus.com",
        "stun.counterpath.com",
        "stun.counterpath.net",
        "stun.ekiga.net",
        "stun.ideasip.com",
        "stun.internetcalls.com",
        "stun.schlund.de",
        "stun.sipgate.net",
        "stun.voip.aebc.com",
        "stun.voiparound.com",
        "stun.voipbuster.com",
        "stun.voipstunt.com",
        "stun.xten.com"
      ],
      "action"           : "allow"
    }
  , {
      "notes"            : "stun servers :10000, from docs: https://docs.syncthing.net/users/config.html#config-option-options.stunserver",
${QSTPROCESS},
      "direction"        : "outgoing",
      "protocol"         : "udp",
      "ports"            : "10000",
      "remote-domains"   : [
        "stun.sipgate.net"
      ],
      "action"           : "allow"
    }
RULE


RELAYS="$(
  join_by "," $(
    jq -r '.relays[].url' endpoint | grep -Eo 'relay://[0-9:.]*' | sed 's#^relay://##' | awk -F: '$2==22067 {print "\"" $1 "\""}'
  )
)"
cat <<RULE
  , {
      "notes"            : "Relay :22067",
${QSTPROCESS},
      "direction"        : "outgoing",
      "protocol"         : "tcp",
      "ports"            : "22067",
      "remote-addresses" : [
        ${RELAYS}
      ],
      "action"           : "allow"
    }
  , {
      "notes"            : "Relay :22067",
${QSTPROCESS},
      "direction"        : "incoming",
      "protocol"         : "tcp",
      "ports"            : "22067",
      "remote-addresses" : [
        ${RELAYS}
      ],
      "action"           : "allow"
    }
RULE



RELAYS="$(
  join_by "," $(
    jq -r '.relays[].url' endpoint | grep -Eo 'relay://[0-9:.]*' | sed 's#^relay://##' | awk -F: '$2==443 {print "\"" $1 "\""}'
  )
)"
cat <<RULE
  , {
      "notes"            : "Relay :443",
${QSTPROCESS},
      "direction"        : "outgoing",
      "protocol"         : "tcp",
      "ports"            : "443",
      "remote-addresses" : [
        ${RELAYS}
      ],
      "action"           : "allow"
    }
  , {
      "notes"            : "Relay :443",
${QSTPROCESS},
      "direction"        : "incoming",
      "protocol"         : "tcp",
      "ports"            : "443",
      "remote-addresses" : [
        ${RELAYS}
      ],
      "action"           : "allow"
    }
RULE

for RELAY in $(jq -r '.relays[].url' endpoint | grep -Eo 'relay://[0-9:.]*' | sed 's#^relay://##' | awk -F: '$2!=22067 && $2 != 443 {print}'); do

RELAY_IP="$(echo $RELAY | awk -F: '{print $1}')"
RELAY_PORT="$(echo $RELAY | awk -F: '{print $2}')"
cat <<RULE
  , {
      "notes"            : "Relay",
${QSTPROCESS},
      "direction"        : "outgoing",
      "protocol"         : "tcp",
      "ports"            : "${RELAY_PORT}",
      "remote-addresses" : [ "${RELAY_IP}" ],
      "action"           : "allow"
    }
RULE
done

################################################################################
# Ending
################################################################################
cat <<RULE
  ]
}
RULE

