#
# letsencrypt.tcl --
#
#   A small Let's Encrypt client for NaviServer implemented in Tcl,
#   supporting the ACME v2 interface of letsenvrypt.
#
#   To use it, set enabled to 1 and drop it somewhere under
#   NaviServer pageroot which is usually /usr/local/ns/pages and point
#   browser to it.
#
# If this page needs to be access restricted, configure the following
# three variables:
#
set user ""
set password ""
set enabled 1

#
# Configuration
#
# "-sslpath":
#     The certificate will be placed finally into this directory.
#     Defaults to: "[ns_info home]/modules/nsssl"
#
# "-API":
#     Can be "staging" (default) or "prodiction"
#     Let's encrypt has several rate limits to avoid DOS
#     situations: https://letsencrypt.org/docs/rate-limits/
#
#     When developing the interface (e.g. improving this script), you
#     should consider using the "staging" API of letsencrypt instead
#     of the "production" API to void these constraints.


set c [::letsencrypt::Client new \
           -API "production" \
           -sslpath "[ns_info home]/modules/nsssl"]
#
# Produce page
#
ns_set update [ns_conn outputheaders] "Expires" "now"

$c getCertificate
$c destroy

#
# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:
