#
# A letsencrypt client based on NaviServer's provided as a NaviServer
# module.
#

package require nx

namespace eval ::letsencrypt {

    nx::Class create ::letsencrypt::Client {

        # state and configuration variables
        :property {domains ""}
        :property {log ""}
        :property {API staging}
        :property {sslpath ""}
        :property {background:switch false}

        # state variables
        :variable domain
        :variable sans

        # crypto state
        :variable modulus
        :variable exponent
        :variable jwk
        :variable thumbprint64

        # results from last HTTP request
        :variable nonce
        :variable replyHeaders
        :variable replyText

        # data for final certificate
        :variable certPrivKey
        :variable certPemFile

        :method init {} {
            if {${:sslpath} eq ""} {
                set :sslpath "[ns_info home]/modules/nsssl"
            }
            if {[info commands ::json::json2dict] eq ""} {
                package require json
            }
        }

        # ####################### #
        # ----- domain form ----- #
        # ####################### #

        :method domainForm {} {
            ns_return 200 text/html [subst {
                <head>
                <title>Let's Encrypt Client</title>
                </head>
                <body>
                <form method='post' action='[ns_conn url]'>
                Please enter the domain names for the SSL certificate:<br>
                <input name="domains" size="80">
                <input type='submit' value='Submit'>
                </form>
                </body>
            }]
        }

        :method log {args} {
            set msg [join $args " "]
            if {!${:background}} {
                ::ns_write $msg
            } else {
                append :log $msg
            }
            ns_log notice "letsencrypt: $msg"
        }


        # ####################### #
        # ----- printHeaders ---- #
        # ####################### #

        :method printHeaders {headers} {
            set result "<pre>"
            foreach {k v} [ns_set array $headers] {
                append result "   $k: [ns_quotehtml $v]\n"
            }
            append result "</pre>\n"
        }

        # ####################### #
        # ------- readFile ------ #
        # ####################### #

        :method readFile {{-binary:switch f} fileName} {
            set F [open $fileName r]
            if {$binary} { fconfigure $F -encoding binary -translation binary }
            set content [read $F]
            close $F
            return $content
        }

        # ####################### #
        # ------- writeFile ----- #
        # ####################### #

        :method writeFile {{-binary:switch f} {-append:switch f} fileName content} {
            set mode [expr {$append ? "a" : "w"}]
            set F [open $fileName $mode]
            if {$binary} { fconfigure $F -encoding binary -translation binary }
            puts -nonewline $F $content
            close $F
        }

        # ################################# #
        # ----- produce backup files -----  #
        # ################################# #

        :method backup {{-mode rename} fileName} {
            set backupFileName ""
            if {[file exists $fileName]} {
                #
                # If the base file exists, make a backup based on the
                # content (using a sha256 checksum). Using checksums
                # is independent of timestamps and makes sure to
                # prevent loss of data (e.g. configuration files). If
                # we have already a backup file, there is nothing to
                # do.
                #
                set backupFileName $fileName.[ns_md file -digest sha256 $fileName]
                if {![file exists $backupFileName]} {
                    file $mode -force $fileName $backupFileName
                    :log "Make backup of $fileName<br>"
                }
            } else {
                #
                # No need to make a backup, file does not exist yet
                #
            }
            return $backupFileName
        }


        # ###############ääää########################## #
        # ----- post JWS request of given payload ----- #
        # ############################################# #

        :method send_signed_request {{-nolog:switch false} {-method POST} url payload} {
            set payload64 [ns_base64urlencode -binary $payload]
            #
            # "kid" and "jwk" are mutually exclusive
            # (https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-6.2)
            #
            if {[info exists :kid]} {
                set protected [subst {{"url":"$url","alg":"RS256","nonce":"${:nonce}","kid":"${:kid}"}}]
            } else {
                #
                # "jwk" only for newAccount and revokeCert requests
                set protected [subst {{"url":"$url","alg":"RS256","nonce":"${:nonce}","jwk":${:jwk}}}]
            }
            set protected64 [ns_base64urlencode $protected]

            set siginput [subst {$protected64.$payload64}]
            set signature64 [::ns_crypto::md string \
                                 -digest sha256 \
                                 -sign ${:accoutKeyFile} \
                                 -encoding base64url \
                                 $siginput]
            set data [subst {{
                "protected": "$protected64",
                "payload":   "$payload64",
                "signature": "$signature64"
            }}]
            #:log "<pre>POST $url\n$data</pre>"

            set queryHeaders [ns_set create]
            ns_set update $queryHeaders "Content-type" "application/jose+json"
            set d [ns_http run -method POST -headers $queryHeaders -body $data $url]

            #
            # Get headers, body and nonce into instance variables,
            # since these are used later to understand what the server
            # replied.
            #
            set :replyHeaders [dict get $d headers]
            set :replyText [dict get $d body]
            set :nonce [ns_set iget ${:replyHeaders} "replay-nonce"]

            if {$nolog} {
                :log "<p>reply from letsencrypt [string length ${:replyText}] bytes</p>"
                #ns_log notice "letsencrypt: reply from letsencrypt:\n${:replyText}"
            } else {
                :log "<pre>reply from letsencrypt:\n${:replyText}</pre>"
            }
            return [dict get $d status]
        }

        :method abortMsg {status msg} {
            :log "$msg ended with HTTP status $status<br>"
            :log "[:printHeaders ${:replyHeaders}]<br>${:replyText}<br>"
        }

        :method startOfReport {} {
            if {!${:background}} {
                ns_headers 200 text/html
            }
            :log \
                {<!DOCTYPE html><html lang="en"><head><title>NaviServer Let's Encrypt client</title></head><body>} \
                "<h3>Obtaining a certificate from Let's Encrypt using" \
                "the [string totitle ${:API}] API:</h3>"
        }

        :method URL {kind} {
            dict get ${:apiURLs} $kind
        }

        # ###################################äää#### #
        # ----- get API URLs from Let's encrypt ---- #
        # ########################################## #

        :method getAPIurls {config} {

            set url [dict get $config ${:API}]
            set d [ns_http run $url]
            set :replyHeaders [dict get $d headers]

            #:log [:printHeaders ${:replyHeaders}]
            set :nonce [ns_set iget ${:replyHeaders} "replay-nonce"]

            set :apiURLs [json::json2dict [dict get $d body]]
            #:log ":apiURLs ${:apiURLs}"

            #
            # key-change keyChange
            # new-authz
            # new-cert    newOrder?
            # new-reg     newAccount?
            # revoke-cert revokeCert
            #             newNonce

            :log [subst {<br>
                Let's Encrypt URLs (${:API} API):<br>
                <pre>   [:URL keyChange]\n   [:URL newNonce]\n   [:URL newOrder]\n   [:URL newAccount]\n   [:URL revokeCert]</pre>
            }]
        }

        :method getNonce {} {
            set d [ns_http run -method HEAD [:URL newNonce]]
            set :replyHeaders [dict get $d headers]
            set :nonce [ns_set iget ${:replyHeaders} "replay-nonce"]
            #:log "<pre>getNonce: ${:nonce}\n</pre>"
        }

        :method decnum_to_bytes {num} {
            set result ""

            while {$num} {
                set char [expr {$num & 0xff}]
                set result "[format %c $char]$result"
                set num [expr {$num >> 8}]
            }
            return $result
        }


        :method parseAccountKey {} {
            :log "parseAccountKey ${:accoutKeyFile}<br>"

            #
            # Get :modulus and :exponent from the PEM file of the account
            #
            set keyInfo [exec openssl rsa -in ${:accoutKeyFile} -noout -text]
            regexp {\nmodulus:\n([\sa-f0-9:]+)\npublicExponent:\s(\d+)\s} $keyInfo . pub_hex exp
            regsub -all {[\s:]} $pub_hex "" mod
            regsub {^00} $mod "" mod
            #:log "<pre>pub_hex: ${pub_hex}</pre>"
            #:log "modulus: ${mod}<br>"

            #
            # Put key info into JSON Web Key (:jwk)
            #
            set :modulus [ns_base64urlencode -binary [binary decode hex $mod]]
            set :exponent [ns_base64urlencode -binary [:decnum_to_bytes $exp]]
            set :jwk [subst {{"e":"${:exponent}","kty":"RSA","n":"${:modulus}"}}]

            #
            # Generate thumbprint from the JSON Web Key (:jwk)
            #
            set :thumbprint64 [ns_md string -digest sha256 -encoding base64url ${:jwk}]
            :log \
                "<br><pre>jwk: ${:jwk}\n" \
                "thumbprint64: ${:thumbprint64}\n"

            #:log "<pre>jwk ${:jwk}\nthumbprint64: ${:thumbprint64}</pre>"
        }

        # ########################################## #
        # - register new acccount at Let's Encrypt - #
        # ########################################## #

        :method registerNewAccount {} {

            :log \
                "Register new account at Let's Encrypt... " \
                "generating RSA key pair...<br>"

            #
            # Repeat max 10 times until registration was successful
            #
            for {set count 0} {$count < 3} {incr count} {
                #
                # Create a fresh account key and get its components
                #
                exec -ignorestderr -- openssl genrsa 2048 > ${:accoutKeyFile}
                :parseAccountKey

                # ########################### #
                # ----- get first nonce ----- #
                # ########################### #
                :getNonce

                # ########################### #
                # ------ registration ------- #
                # ########################### #
                :log "Creating new registration...<br>"

                set payload [subst {{"termsOfServiceAgreed": true, "onlyReturnExisting": false, "contact": \["mailto:webmaster@${:domain}"\]}}]
                set status [:send_signed_request [:URL newAccount] $payload]
                if {$status eq "400"} {
                    :log "New Registration failed. Retry and generate new RSA key pair...<br>"
                } else {
                    set :kid [ns_set iget ${:replyHeaders} "location"]
                    :log "<pre>registration headers contained kid ${:kid}\n</pre>"
                    break
                }
            }
            :log "Registration ended with status $status.<br>"

            return $status
        }

        # ########################## #
        # ----- sign agreement ----- #
        # ########################## #

        :method signAgreement {} {

            :log "<br>Signing agreement... "
            set location [ns_set iget ${:replyHeaders} "location"]
            #set :kid $location

            #
            # parse link header for terms of service
            #
            set url ""
            foreach {key value} [ns_set array ${:replyHeaders}] {
                if {$key eq "link"
                    && [regexp {^<(.*)>;rel="terms-of-service"} $value . url]
                } {
                    break
                }
            }

            set payload [subst {{"resource": "reg", "agreement": "$url"}}]
            set httpStatus [:send_signed_request $location $payload]

            :log "returned HTTP status $httpStatus<br>"
            return $httpStatus
        }


        # ########################## #
        # ----- authorize domain --- #
        # ########################## #

        :method authorizeDomain {auth_url domain} {
            :log "<br>Authorizing account for domain <strong>$domain</strong>... "

            set httpStatus [:send_signed_request $auth_url ""]
            :log "$auth_url returned HTTP status $httpStatus<br>"

            if {$httpStatus in {400 403}} {
                :log "error message: ${:replyText}<br>"
                return invalid
            }

            :log "... getting HTTP challenge... "
            set :authorization [ns_set iget ${:replyHeaders} "location"]
            set challenges [dict get [json::json2dict ${:replyText}] challenges]
            ns_log notice "... challenges:\n[join $challenges \n]"

            #
            # Parse HTTP challenge
            #
            foreach entry $challenges {
                if {[dict filter $entry value "http-01"] ne ""} {
                    set challengeURL [dict get $entry url]
                    set token [dict get $entry token]
                }
            }

            #
            # Provide HTTP resource to fulfill HTTP challenge
            #
            file mkdir [ns_server pagedir]/.well-known/acme-challenge
            :writeFile [ns_server pagedir]/.well-known/acme-challenge/$token $token.${:thumbprint64}

            :log "<pre>keyauthorization: $token.${:thumbprint64}</pre>\n"

            #set payload [subst {{"resource": "challenge", "keyAuthorization": "$token.${:thumbprint64}"}}]
            :log "challenge is done [ns_server pagedir]/.well-known/acme-challenge/$token<br>"

            #
            # Try to obtain challenge URL locally. If this does not
            # work for us, it will not work for letsencrypt either.
            #
            set wellknown_url "http://$domain/.well-known/acme-challenge/$token"
            set d [ns_http run -timeout 5.0 $wellknown_url]
            :log "local test pf wellknown_url $wellknown_url returned <pre>$d</pre>"
            if {[dict get $d status] eq "200"} {
                :log "challenge is available on local server $wellknown_url\n"
            } else {
                :log "challenge can not retrieved from local server: $wellknown_url\n"
                return "invalid"
            }

            set httpStatus [:send_signed_request $challengeURL "{}"]
            :log "challengeURL $challengeURL returned HTTP status $httpStatus<br>"

            #
            # ----- validate
            #
            :log "... validating the challenge... "
            #:log "Reply Headers: [:printHeaders ${:replyHeaders}]<br>"

            #
            # Not sure, we have to get the "up" link, the result is
            # identical to the $auth_url
            #
            #set link ""
            #foreach {k v} [ns_set array ${:replyHeaders}] {
            #    if {$k eq "link" && [regexp {^<(.*)>;rel="up"} $v . link]} {
            #        break
            #    }
            #}
            #if {$link ne ""} {
            #    :log "obtained up link: $link, "
            #} else {
            #    :log "could not obtain up link from header, "
            #}
            #:log "uplink equal to auth_url: [string equal $link $auth_url]<br>"

            set status [dict get [json::json2dict ${:replyText}] status]
            :log "status: $status<br>"
            #:log "<pre>$result</pre>[:printHeaders ${:replyHeaders}]<br>"

            # check until validation is finished (max 20 times)
            set count 0
            #set link $challengeURL
            while {$status eq "pending"} {
                :log "... retry after one second... "
                ns_sleep 1

                set httpStatus [:send_signed_request $auth_url ""]
                :log "$auth_url returned HTTP status $httpStatus<br>"

                set status [dict get [json::json2dict ${:replyText}] status]
                :log "status: $status<br>"
                if {$status ni {"valid" "pending"}} {
                    :log "<pre>${:replyText}</pre>[:printHeaders ${:replyHeaders}]<br>"
                    break
                }
                # safety belt to avoid in the worst case endless loops.
                if {[incr count] > 2} break
            }
            return $status
        }


        # ########################### #
        # ----- get certificate ----- #
        # ########################### #

        :method certificateRequest {finalizeURL} {

            :log "<br>Generating RSA key pair for SSL certificate... "

            #
            # Repeat max 10 times until certificate was successfully obtained
            #
            for {set count 0} {$count < 10} {incr count} {

                set csrConfFile ${:sslpath}/${:domain}.csr.conf
                set csrFile     ${:sslpath}/${:domain}.csr
                set keyFile     ${:sslpath}/${:domain}.key

                ns_log notice "call: openssl genrsa -out $keyFile 2048"
                set :certPrivKey [:readFile $keyFile]

                lassign [exec openssl version -d] _ openssldir
                file copy -force [file join $openssldir openssl.cnf] $csrConfFile
                if {[llength ${:sans}] > 0} {
                    set altNames {}; foreach alt ${:sans} {lappend altNames DNS:$alt}
                    :writeFile -append $csrConfFile "\n\[SAN\]\nsubjectAltName=[join $altNames ,]\n"
                    set extensions [list -reqexts SAN -extensions SAN]
                } else {
                    set extensions {}
                }
                ns_log notice [subst {call: openssl req -new -sha256 -outform DER {*}$extensions \
                                          -subj "/CN=${:domain}" -key $keyFile -config $csrConfFile -out $csrFile}]
                exec openssl req -new -passout pass:"" -sha256 -outform DER {*}$extensions \
                    -subj "/CN=${:domain}" -key $keyFile -config $csrConfFile -out $csrFile 2>@1
                set csr [:readFile -binary ${:sslpath}/${:domain}.csr]

                :log "DONE<br>"
                :log "Getting the certificate for domain ${:domain}, SANs ${:sans}... "

                set csr64 [ns_base64urlencode -binary $csr]
                set payload [subst {{"csr": "$csr64"}}]
                set httpStatus [:send_signed_request $finalizeURL $payload]

                :log "returned HTTP status $httpStatus<br>"

                if {$httpStatus eq "400"} {
                    :log "Certificate request failed. Generating new RSA key pair... "
                    #ns_log notice "CSR-Request returned 400\n"
                    :log "[:printHeaders ${:replyHeaders}]<br>${:replyText}<br>"
                    break
                } else {
                    break
                }
            }
            if {$httpStatus == 200} {
                set finalizeDict [json::json2dict ${:replyText}]
                set certificateURL [dict get $finalizeDict certificate]
                set httpStatus [:send_signed_request -nolog $certificateURL ""]
            }
            return $httpStatus
        }


        # ############################### #
        # ----- install certificate ----- #
        # ############################### #

        :method certificateInstall {} {

            :log "<br>Generate the certificate under ${:sslpath}...<br>"

            set cert ${:replyText}

            #ns_log notice  "Storing certificate under ${:sslpath}/${:domain}.cer"
            #:writeFile ${:sslpath}/${:domain}.pem ${:replyText}

            #puts "Converting the certificate to PEM format to ${:sslpath}/${:domain}.crt"
            #exec openssl x509 -inform der \
                #    -in ${:sslpath}/${:domain}.cer \
                #    -out ${:sslpath}/${:domain}.crt
            #set cert [:readFile ${:sslpath}/${:domain}.crt]

            #
            # Build certificate in the filesystem. Backup old file if necessary.
            #
            if {${:API} eq "production"} {
                set :certPemFile ${:sslpath}/${:domain}.pem
            } else {
                #
                # In the case, we use the staging interface, we never
                # want to overwrite non-staging certificates.
                #
                set :certPemFile ${:sslpath}/${:API}-${:domain}.pem
            }

            # Save certificate and private key in single file in directory
            # of nsssl module.
            :backup ${:certPemFile}

            ns_log notice  "Combining certificate and private key to ${:certPemFile}"
            :writeFile ${:certPemFile} "${:certPrivKey}$cert"

            #ns_log notice  "Deleting ${:domain}.cer and ${:domain}.crt under ${:sslpath}/"
            #file delete ${:sslpath}/${:domain}.cer
            #file delete ${:sslpath}/${:domain}.crt

            #
            # Get certificate chain; the Let's Encrypt certificates
            # are available from https://letsencrypt.org/certificates/
            # the used certificate is the "Let’s Encrypt Authority X3
            # (IdenTrust cross-signed)"
            #
            # One might as well add the following certificate to
            # complete the chain, but this does not seem necessary by
            # www.ssllabs.com
            #
            # https://www.identrust.com/certificates/trustid/root-download-x3.html
            #
            #set letsencrypt_intermediate https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt
            #set letsencrypt_intermediate https://letsencrypt.org/certs/trustid-x3-root.pem.txt
            #:log "Obtaining certificate chain ... "
            #set d [ns_http run $letsencrypt_intermediate]
            #:log "returned HTTP status [dict get $d status]<br>"
            #
            #:writeFile -append ${:certPemFile} [dict get $d body]

            #
            # Add DH parameters
            #
            :log "Adding DH parameters to ${:certPemFile} (might take a while - wait for DONE message) ... "
            exec -ignorestderr -- openssl dhparam 2048 >> ${:certPemFile} 2> /dev/null
            :log " DONE<br><br>"

            :log "New certificate successfully installed in: <strong>${:certPemFile}</strong><br><br>"
        }


        # ############################### #
        # ----- Update configuration ---- #
        # ############################### #

        :method updateConfiguration {} {

            #
            # Update the NaviServer config file by reading its content
            # and update it in memory before writing it back to disk
            # (if changed).
            #

            :log "Checking the NaviServer config file: "
            set C [:readFile [ns_info config]]
            set origConfig $C

            #
            # Check, if nsssl module is already loaded
            #
            set nssslLoaded 0
            foreach d [ns_driver info] {
                if {[dict get $d protocol] eq "https"} {
                    set nssslLoaded 1
                    break
                }
            }
            if {$nssslLoaded} {
                :log "The nsssl driver module is apparently already loaded.<br>"
            } else {
                :log "The nsssl driver module is apparently already not loaded, try to fix this.<br>"

                if {[regexp {\#\s+ns_param\s+nsssl.*nsssl} $C]} {
                    #
                    # The nsssl driver is apparently commented out, activate it
                    #
                    regsub {\#(\s+ns_param\s+nsssl.*nsssl)} $C \1 C
                    :log {...removing comment from driver module nsssl.so line in config file.<br>}

                } else {
                    #
                    # There is no nsssl driver in the config file, add it
                    # to the end.
                    #
                    append C {
                        #
                        # In order to install nsssl globally to your
                        # server, uncomment the following lines
                        #
                        ns_section "ns/modules"
                        ns_param    nssock              nssock

                        ns_section    ns/server/${server}/modules
                        ns_param      nsssl            nsssl.so
                    }
                    :log {
                        ... add the driver module "nsssl.so" in your config file either
                        to the global or per-server "modules" section .<br>}
                }
            }

            if {![regexp {ns_param\s+certificate\s+} $C]} {
                :log [subst {Your config file [ns_info config] does
                    not seem to contain a nsssl definition section.<br>
                    Adding a default section to the end. Please check,
                    if you want to modify the section according to your needs.
                }]
                append C [subst {
                    ns_section    ns/server/\${server}/module/nsssl
                    ns_param   certificate   ${:certPemFile}
                    ns_param   address       0.0.0.0
                    ns_param   port          443
                    ns_param   ciphers      "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!RC4"
                    ns_param   protocols    "!SSLv2:!SSLv3"
                    ns_param   verify         0

                    ns_param   extraheaders {
                        Strict-Transport-Security "max-age=31536000; includeSubDomains"
                        X-Frame-Options SAMEORIGIN
                        X-Content-Type-Options nosniff
                    }
                }]
            } elseif {![regexp "ns_param\\s+certificate\\s+${:certPemFile}" $C]} {
                :log "... updating the certificate entry (need 'ns_param certificate ${:certPemFile}')<br>"
                regsub -all {ns_param\s+certificate\s+[^\n]+} $C "ns_param   certificate   ${:certPemFile}" C
            }

            #
            # Rewrite config file only, when the content has changed
            #
            if {$origConfig ne $C} {
                if {![file writable [ns_info config]]} {
                    :log \
                        "<p><strong>Warning:</strong> cannot update [ns_info config]" \
                        "since it is not writable<p>"
                } elseif {${:API} eq "staging"} {
                    :log \
                        "<p><strong>Warning:</strong> no automated updates on [ns_info config]" \
                        "when using the 'staging' environment<p>"
                } else {
                    #
                    # Make first a backup of old config file ...
                    #
                    :backup -mode copy [ns_info config]

                    #
                    # Rewrite config file
                    #
                    :writeFile [ns_info config] $C
                    :log [ns_trim -delimiter | [subst {
                        |Updating NaviServer config file<br>
                        |Please check updated config file: <strong>[ns_info config]</strong>
                        |<br>and update it (if necessary)<p>
                    }]]
                }
            } else {
                #
                # Nothing has changed.
                #
                :log {No need to update the NaviServer configuration file.<br>}
            }
        }


        # ########################## #
        # ----- MAIN METHOD ----- #
        # ########################## #
        :public method getCertificate {} {
            #
            # This method does all the steps required to obtain a
            # certificate, such as
            #
            # - selecting the API (production or staging),
            # - registering a new account if necessary,
            # - create public and private key for the account,
            # - issuing a certificate request,
            # - obtaining the certificate, and
            # - installing the certificate.
            #
            # If called interactivaly, the progress is logged to the
            # console, otherwise just into the system log.
            #
            ns_log notice "letsencrypt client: domains <${:domains}> background ${:background}"

            if {${:domains} eq ""} {
                #
                # Are values for the domains specified in the
                # NaviServer configuration file?
                #
                set :domains [ns_config ns/server/[ns_info server]/module/letsencrypt domains]
                #ns_log notice "letsencrypt client: domains from NaviServer configuration file: <${:domains}>"

            }

            if {${:domains} eq "" && [ns_conn isconnected]} {
                #
                # Still no values. Try to get it from the query parameters
                #
                #ns_log notice "letsencrypt client: we need a queryget"
                set :domains [ns_queryget domains ""]
                ns_log notice "letsencrypt client: domains from query <${:domains}> background ${:background}"
                #
                # If the domain names were already submitted in the form
                # (or via query parameters), we have all data we
                # need.
            }

            ns_log notice "letsencrypt client: domains <${:domains}> background ${:background}"
            if {${:domains} eq ""} {
                #
                # If we have still no values, provide the user with a
                # form to fill-in the data and to continue from there.
                # But this works only, when we are not called in the
                # background.
                #
                if {${:background}} {
                    error "letsencrypt: either provide '-domains ...' or run from a connection thread"
                }
                ns_log notice "letsencrypt: have to return domainForm"
                :domainForm
                return
            }

            set :domain    [lindex ${:domains} 0]
            set :sans      [lrange ${:domains} 1 end]

            set config {
                staging    {https://acme-staging-v02.api.letsencrypt.org/directory}
                production {https://acme-v02.api.letsencrypt.org/directory}
            }

            #
            # Make sure, the sslpath exists
            #
            file mkdir ${:sslpath}
            set :accoutKeyFile ${:sslpath}/letsencrypt-${:API}-account.key
            ns_log notice "letsencrypt client: call start of report"

            #
            # Start output
            #
            :startOfReport

            ns_log notice "letsencrypt: getAPIurls"

            #
            # Always get first the API URLs
            #
            :getAPIurls $config

            #
            # Create or reuse an account
            #
            if {[file exists ${:accoutKeyFile}]} {
                #
                # We have already registered in the past successfully at
                # Let's Encrypt and signed the agreement.
                #
                :log "Reuse existing account registration at Let's Encrypt (${:accoutKeyFile})<br>"

                :parseAccountKey
                :getNonce

                set payload [subst {{"termsOfServiceAgreed": true, "onlyReturnExisting": true, "contact": \["mailto:webmaster@${:domain}"\]}}]
                set status [:send_signed_request [:URL newAccount] $payload]

                if {$status eq "400"} {
                    :abortMsg $status "authorization for existing account failed"
                    return
                } else {
                    set :kid [ns_set iget ${:replyHeaders} "location"]
                    :log "<pre>registration headers contained kid ${:kid}\n</pre>"
                }

            } else {

                set status [:registerNewAccount]
                if {$status >= 400} {
                    :abortMsg $status "Registration"
                    return
                }

                set status [:signAgreement]
                if {$status >= 400} {
                    :abortMsg $status "Agreement"
                    return
                }
            }

            #
            # Create a new order for the domains
            #
            file delete -force [ns_server pagedir]/.well-known
            file mkdir [ns_server pagedir]/.well-known

            :log "Creating new order...<br>"
            set ids {}
            foreach domain ${:domains} {
                lappend ids [subst {{"type": "dns", "value": "$domain"}}]
            }
            set payload [subst {{"identifiers": \[[join $ids ,]\]}}]
            :log "... payload: <pre>$payload</pre>"

            set httpStatus [:send_signed_request [:URL newOrder] $payload]
            if {$httpStatus >= 400} {
                :abortMsg $httpStatus "Order failed"
                return
            }
            set orderDict [json::json2dict ${:replyText}]
            set authorizations [dict get $orderDict authorizations]
            set identifiers [dict get $orderDict identifiers]
            set orderFinalizeURL [dict get $orderDict finalize]

            #:log "<pre>authorizations:\n$authorizations\norderFinalizeURL:$orderFinalizeURL</pre>"

            if {[llength $authorizations] != [llength ${:domains}]} {
                :abortMsg $httpStatus "number of domains ([llength ${:domains}]) differs from number of authorizations ([llength $authorizations])"
                return
            }

            foreach domain ${:domains} auth_url $authorizations id $identifiers {
                set status [:authorizeDomain $auth_url [dict get $id value]]
                if {$status in {invalid}} {
                    :log [ns_trim -delimiter | [subst {
                        |Validation of domain $domain failed (final status $status).
                        |<p>Please issue a corrected certificate check.
                    }]]
                    return
                }
            }

            file delete -force [ns_server pagedir]/.well-known

            #
            # Get certificate
            #
            set status [:certificateRequest $orderFinalizeURL]
            if {$status >= 400} {
                :abortMsg $status "Certificate request"
                return
            }

            #
            # Install certificate and update configuration file
            #
            :certificateInstall
            :updateConfiguration

            if {${:API} eq "production"} {
                #
                # Everything was updated, We can trigger the reload
                # operation by sending SIGHUP to the nsd process
                #
                ns_kill [pid] 1
                :log [ns_trim -delimiter | [subst {
                    |<br>The new certificate is installed and was
                    |reloaded via SIGHUP. For old versions of
                    |NaviServer, restart your NaviServer instance and
                    |check results on
                    |<a href="https://${:domain}">https://${:domain}</a>.
                    |<p> }]]

                :log "<p>Certificate were reloaded by sending SIGHUP to nsd"
            } else {
                :log "<p><strong>Warning:</strong> no automated reloading" \
                    "when using the 'staging' environment<p>"
            }
        }
    }
}

#
# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:
