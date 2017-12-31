#
# letsencrypt.tcl --
#
#   A small Let's Encrypt client for NaviServer implemented in Tcl.
#   To use it, set enabled to 1 and drop it somewhere under
#   NaviServer pageroot which is usually /usr/local/ns/pages and point
#   browser to it.
#
#
# If this page needs to be restricted, configure the following three variables:
#
set user ""
set password ""
set enabled 1

namespace eval ::letsencrypt {
    #
    # The certificate will be placed finally into the following
    # directory:
    #
    set sslpath "[ns_info home]/modules/nsssl"

    #
    # Let's encrypt has several rate limits to avoid DOS
    # situations: https://letsencrypt.org/docs/rate-limits/
    #
    # When developing the interface (e.g. improving this script), you
    # might consider using the staging API of letsencrypt instead of
    # the production API to void these constraints.
    #
    set API "production"
    #set API "staging"
}

##########################################################################
#
#  ---- no configuation below this point ---------------------------------
#
##########################################################################

package require json
package require pki
package require nx

namespace eval ::letsencrypt {

    nx::Class create ::letsencrypt::Client {

        # state and configuration variables
        :variable domains
        :variable domain
        :variable sans
        :variable startUrl

        # crypto state
        :variable rsa_key
        :variable modulus
        :variable exponent

        # results from last HTTP request
        :variable nonce
        :variable replyHeaders
        :variable replyText

        # data for final certificate
        :variable certPrivKey
        :variable certPemFile


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
            if {$binary} { fconfigure $F -translation binary }
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
            if {$binary} { fconfigure $F -translation binary }
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
                # content (using a sha256 checksum). Using checksums is
                # independent of timestamps and makes sure to prevent loss
                # of data (e.g. config files). If we have already a backup
                # file, there is nothing to do.
                #
                set backupFileName $fileName.[ns_md file -digest sha256 $fileName]
                if {![file exists $backupFileName]} {
                    file $mode -force $fileName $backupFileName
                    ns_write "Make backup of $fileName<br>"
                }
            } else {
                #
                # No need to make a backup, file does not exist yet
                #
            }
            return $backupFileName
        }

        # ################################# #
        # ----- base64url converting -----  #
        # ################################# #
        :method base64url {data} {
            return [string map {+ - / _ = {} \n {}} [ns_base64encode $data]]
        }

        # ############################## #
        # ----- JSON web signature ----- #
        # ############################## #
        :method JWS {payload} {
            #
            # Generate JSON Web Signature (JWS) according to RFC 7515
            # based on instance variables nonce, modulus, and
            # exponent.
            #
            set jwk [subst {{
                "kty": "RSA",
                "n": "${:modulus}",
                "e": "${:exponent}"
            }}]

            # build protected header
            set protected [subst {{"nonce": "${:nonce}"}}]
            set protected64 [:base64url $protected]

            # build payload and input for signature
            set payload64 [:base64url $payload]
            set siginput [subst {$protected64.$payload64}]

            # build signature
            set signature [pki::sign $siginput ${:rsa_key} sha256]
            set signature64 [:base64url $signature]

            # build json web signature
            set jws [subst {{
                "header": {
                    "alg": "RS256",
                    "jwk": $jwk
                },
                "protected": "$protected64",
                "payload":   "$payload64",
                "signature": "$signature64"
            }}]

            #ns_log notice "JWS payload:\n$payload\njws:\n$jws"
            return $jws
        }

        # ###############ääää########################## #
        # ----- post JWS request of given payload ----- #
        # ############################################# #

        :method postJwsRequest {url payload} {
            set queryHeaders [ns_set create]
            set :replyHeaders [ns_set create]
            ns_set update $queryHeaders "Content-type" "application/jose+json"

            # submit post request
            set id [ns_http queue -method POST \
                        -headers $queryHeaders \
                        -body [:JWS $payload] \
                        $url]
            ns_http wait -status S -result :replyText -headers ${:replyHeaders} $id

            # keep the nonce for the next request
            set :nonce [ns_set iget ${:replyHeaders} "replay-nonce"]

            # return status
            return $S
        }


        :method abortMsg {status msg} {
            ns_write "$msg ended with HTTP status $status<br>"
            ns_write "[:printHeaders ${:replyHeaders}]<br>${:replyText}<br>"
        }

        :method startOfReport {} {
            ns_headers 200 text/html
            ns_write {<html lang="en"><head><title>NaviServer Let's Encrypt client</title></head><body>}
            ns_write "<h3>Obtaining a certificate from Let's Encrypt using \
                  the [string totitle $::letsencrypt::API] API:</h3>"
        }

        :method URL {kind} {
            dict get ${:apiURLs} $kind
        }

        # ###################################äää#### #
        # ----- get API urls from Let's encrypt ---- #
        # ########################################## #

        :method getAPIurls {config} {


            set url [dict get $config $::letsencrypt::API url]

            set :replyHeaders [ns_set create]
            set id [ns_http queue $url]
            ns_http wait -status S -result R -headers ${:replyHeaders} $id

            #ns_write [:printHeaders ${:replyHeaders}]
            set :nonce [ns_set iget ${:replyHeaders} "replay-nonce"]

            set :apiURLs [json::json2dict $R]

            ns_write [subst {<br>
                Let's Encrypt URLs:<br>
                <pre>   [:URL key-change]\n   [:URL new-authz]\n   [:URL new-cert]\n   [:URL new-reg]\n   [:URL revoke-cert]</pre>
            }]
        }

        # ########################################## #
        # - register new acccount at Let's Encrypt - #
        # ########################################## #

        :method registerNewAccount {config} {

            ns_write "Register new account at Let's Encrypt... "
            ns_write "generating RSA key pair...<br>"

            #
            # Repeat max 10 times until registration was successful
            #
            for {set count 0} {$count < 10} {incr count} {
                set :rsa_key [pki::rsa::generate 2048]
                set :modulus  [:base64url [::pki::_dec_to_ascii [dict get ${:rsa_key} n]]]
                set :exponent [:base64url [::pki::_dec_to_ascii [dict get ${:rsa_key} e]]]

                # ##################### #
                # ----- get nonce ----- #
                # ##################### #
                set :replyHeaders [ns_set create]
                set id [ns_http queue -method HEAD [:URL new-reg]]
                ns_http wait -status S -result R -headers ${:replyHeaders} $id
                set :nonce [ns_set iget ${:replyHeaders} "replay-nonce"]

                # ######################## #
                # ----- registration ----- #
                # ######################## #
                ns_write "Creating new registration...<br>"
                #ns_log notice  "REGISTRATION:"

                set payload [subst {{"resource": "new-reg", "contact": \["mailto:webmaster@${:domain}"\]}}]
                set status [:postJwsRequest [:URL new-reg] $payload]

                if {$status eq "400"} {
                    ns_write "Registration failed. Retry and generate new RSA key pair...<br>"
                } else {
                    break
                }
            }
            ns_write "Registration ended with status $status.<br>"

            return $status
        }

        # ########################## #
        # ----- sign agreement ----- #
        # ########################## #

        :method signAgreement {} {

            ns_write "<br>Signing agreement... "
            set location [ns_set iget ${:replyHeaders} "location"]

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
            set httpStatus [:postJwsRequest $location $payload]

            ns_write "returned HTTP status $httpStatus<br>"
            return $httpStatus
        }


        # ########################## #
        # ----- authorize domain --- #
        # ########################## #

        :method authorizeDomain {domain} {
            ns_write "<br>Authorizing account for domain <strong>$domain</strong>... "

            set payload [subst {{"resource": "new-authz", "identifier": {"type": "dns", "value": "$domain"}}}]
            set httpStatus [:postJwsRequest [:URL new-authz] $payload]
            ns_write "returned HTTP status $httpStatus<br>"

            ns_write "... getting HTTP challenge... "
            set :authorization [ns_set iget ${:replyHeaders} "location"]
            set challenges [dict get [json::json2dict ${:replyText}] challenges]

            #
            # parse HTTP challenge
            #
            foreach entry $challenges {
                if {[dict filter $entry value "http-01"] ne ""} {
                    set url [dict get $entry uri]
                    set token [dict get $entry token]
                }
            }

            #
            # generate thumbprint
            #
            set pk [subst {{"e":"${:exponent}","kty":"RSA","n":"${:modulus}"}}]
            set thumbprint [binary format H* [ns_md string -digest sha256 $pk]]
            set thumbprint64 [:base64url $thumbprint]

            #
            # provide HTTP resource to fulfill HTTP challenge
            #
            file mkdir [ns_server pagedir]/.well-known/acme-challenge
            :writeFile [ns_server pagedir]/.well-known/acme-challenge/$token $token.$thumbprint64

            set payload [subst {{"resource": "challenge", "keyAuthorization": "$token.$thumbprint64"}}]
            set httpStatus [:postJwsRequest $url $payload]
            ns_write "returned HTTP status $httpStatus<br>"

            #
            # ----- validate
            #
            ns_write "... validating the challenge... "

            regexp {^<(.*)>;rel="up"} [ns_set iget ${:replyHeaders} "link"] . url
            set status [dict get [json::json2dict ${:replyText}] status]

            ns_write "status: $status<br>"
            #ns_write "<pre>$result</pre>[:printHeaders ${:replyHeaders}]<br>"

            # check until validation is finished
            while {$status eq "pending"} {
                ns_write "... retry after one second... "
                ns_sleep 1

                set id [ns_http queue $url]
                ns_http wait -status S -result R -headers ${:replyHeaders} $id
                set :nonce [ns_set iget ${:replyHeaders} "replay-nonce"]

                set status [dict get [json::json2dict $R] status]
                ns_write "status: $status<br>"
                if {$status ni {"valid" "pending"}} {
                    ns_write "<pre>$R</pre>[:printHeaders ${:replyHeaders}]<br>"
                    break
                }
            }
            return $status
        }


        # ########################### #
        # ----- get certificate ----- #
        # ########################### #

        :method certificateRequest {} {

            ns_write "<br>Generating RSA key pair for SSL certificate... "

            #
            # Repeat max 10 times until certificate was successfully obtained
            #
            for {set count 0} {$count < 10} {incr count} {

                set csrViaOpenSLL 1
                if {$csrViaOpenSLL} {
                    set csrConfFile $::letsencrypt::sslpath/${:domain}.csr.conf
                    set csrFile     $::letsencrypt::sslpath/${:domain}.csr
                    set keyFile     $::letsencrypt::sslpath/${:domain}.key

                    exec -ignorestderr openssl genrsa -out $keyFile 2048
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
                    exec openssl req -new -sha256 -outform DER {*}$extensions \
                        -subj "/CN=${:domain}" -key $keyFile -config $csrConfFile -out $csrFile
                    set csr [:readFile -binary $::letsencrypt::sslpath/${:domain}.csr]

                } else {
                    set cert_key [pki::rsa::generate 2048]
                    set csr [pki::pkcs::create_csr $cert_key [list CN ${:domain}] 0]
                    set :certPrivKey [pki::key $cert_key]
                }
                ns_write "DONE<br>"
                ns_write "Getting the certificate for domain ${:domain}, SANs ${:sans}... "

                set csr64 [:base64url $csr]
                set payload [subst {{"resource": "new-cert", "csr": "$csr64", "authorizations": "${:authorization}"}}]
                set httpStatus [:postJwsRequest [:URL new-cert] $payload]
                ns_write "returned HTTP status $httpStatus<br>"

                if {$httpStatus eq "400"} {
                    ns_write "Certificate request failed. Generating new RSA key pair... "
                    #ns_log notice "CSR-Request returned 400\n"
                    ns_write "[:printHeaders ${:replyHeaders}]<br>${:replyText}<br>"

                } else {
                    break
                }
            }
            return $httpStatus
        }


        # ############################### #
        # ----- install certificate ----- #
        # ############################### #

        :method certificateInstall {} {

            ns_write "<br>Generate the certificate under $::letsencrypt::sslpath...<br>"

            ns_log notice  "Storing certificate under $::letsencrypt::sslpath/${:domain}.cer"
            :writeFile -binary $::letsencrypt::sslpath/${:domain}.cer ${:replyText}

            puts "Converting the certificate to PEM format to $::letsencrypt::sslpath/${:domain}.crt"
            exec openssl x509 -inform der \
                -in $::letsencrypt::sslpath/${:domain}.cer \
                -out $::letsencrypt::sslpath/${:domain}.crt
            set cert [:readFile $::letsencrypt::sslpath/${:domain}.crt]

            #
            # Build certificate in the file system. Backup old file if necessary.
            #
            set :certPemFile $::letsencrypt::sslpath/${:domain}.pem
            :backup ${:certPemFile}

            # Save certificate and private key in single file in directory
            # of nsssl module

            ns_log notice  "Combining certificate and private key to ${:certPemFile}"
            :writeFile ${:certPemFile} "$cert${:certPrivKey}"

            ns_log notice  "Deleting ${:domain}.cer and ${:domain}.crt under $::letsencrypt::sslpath/"
            file delete $::letsencrypt::sslpath/${:domain}.cer
            file delete $::letsencrypt::sslpath/${:domain}.crt

            #
            # Get certificate chain; the Let's Encrypt certificates are
            # available from https://letsencrypt.org/certificates/
            # the used certificate is the "Let’s Encrypt Authority X3 (IdenTrust cross-signed)"
            #
            # One might as well add the following certificate to complete
            # the chain, but thos does not seem necessary by
            # www.ssllabs.com
            #
            # https://www.identrust.com/certificates/trustid/root-download-x3.html
            #
            ns_write "Obtaining certificsate chain ... "
            set id [ns_http queue https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt]
            ns_http wait -status S -result R $id
            ns_write "returned HTTP status $S<br>"

            :writeFile -append ${:certPemFile} $R

            #
            # Add DH parameters
            #
            ns_write "Adding DH parameters to ${:certPemFile} (might take a while) ... "
            exec -ignorestderr -- openssl dhparam 2048 >> ${:certPemFile} 2> /dev/null
            ns_write " DONE<br><br>"

            ns_write "New certificate successfully installed in: <strong>${:certPemFile}</strong><br><br>"
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

            ns_write "Checking the NaviServer config file: "
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
                ns_write "The nsssl driver module is apparently already loaded.<br>"
            } else {
                ns_write "The nsssl driver module is apparently already not loaded, try to fix this.<br>"

                if {[regexp {\#\s+ns_param\s+nsssl.*nsssl[.]so} $C]} {
                    #
                    # The nsssl driver is apparently commented out, activate it
                    #
                    regsub {\#(\s+ns_param\s+nsssl.*nsssl[.]so)} $C \1 C
                    ns_write {...removing comment from driver module nsssl.so line in config file.<br>}

                } else {
                    #
                    # There is no nsssl driver in the config file, add it
                    # to the end.
                    #
                    append C {
                        ns_section    ns/server/${server}/modules
                        ns_param      nsssl            nsssl.so
                    }
                    ns_write {... adding driver module nsssl.so to your config file.<br>}
                }
            }

            if {![regexp {ns_param\s+certificate\s+} $C]} {
                ns_write [subst {Your config file [ns_info config] does
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
                ns_write {... updating the certificate entry<br>}
                regsub -all {ns_param\s+certificate\s+[^\n]+} $C "ns_param   certificate   ${:certPemFile}" C
            }

            #
            # Rewrite config file only, when the content has changed
            #
            if {$origConfig ne $C} {
                #
                # Make first a backup of old config file ...
                #
                :backup -mode copy [ns_info config]

                #
                # Rewrite config file
                #
                :writeFile [ns_info config] $C
                ns_write [subst {
                    Updating NaviServer config file<br>
                    Please check updated config file: <strong>[ns_info config]</strong>
                    <br>and update it (if necessary)<p>
                }]
            } else {
                #
                # Nothing has changed.
                #
                ns_write {No need to update the NaviServer config file.<br>}
            }
        }


        # ########################## #
        # ----- MAIN METHOD ----- #
        # ########################## #
        :public method getCertificate {} {

            set :domains [ns_queryget domains]
            #
            # If the domain names were already submitted in the form
            # (or via query parameters), we have all data we
            # need. Otherwise give the user a form to fill in the data
            # and to continue from there.

            if {${:domains} eq ""} {
                :domainForm
                return
            }

            set :domain    [lindex ${:domains} 0]
            set :sans      [lrange ${:domains} 1 end]
            set :startUrl "[ns_conn proto]://${:domain}[ns_conn url]"

            set config {
                staging    {url https://acme-staging.api.letsencrypt.org/directory}
                production {url https://acme-v01.api.letsencrypt.org/directory}
            }

            #
            # Make sure, the sslpath exists
            #
            file mkdir $::letsencrypt::sslpath

            set signatureKeyFile $::letsencrypt::sslpath/letsencrypt-$::letsencrypt::API-account-signature.key

            #
            # Start output
            #
            :startOfReport

            #
            # Always get first the API urls
            #
            :getAPIurls $config

            #
            # Create or reuse an account
            #
            if {[file exists $signatureKeyFile]} {
                #
                # We have already registered in the past successfully at
                # Let's Encrypt and signed the agreement.
                #
                ns_write "Reuse existing account registration at Let's Encrypt<br>"

                eval [:readFile $signatureKeyFile]
                set :rsa_key $rsa_key
                set :modulus  [:base64url [::pki::_dec_to_ascii [dict get ${:rsa_key} n]]]
                set :exponent [:base64url [::pki::_dec_to_ascii [dict get ${:rsa_key} e]]]

            } else {

                set status [:registerNewAccount $config]
                if {$status >= 400} {
                    :abortMsg $status "Registration"
                    return
                }

                set status [:signAgreement]
                if {$status >= 400} {
                    :abortMsg $status "Agreement"
                    return
                }
                :writeFile $signatureKeyFile [list set rsa_key ${:rsa_key}]\n
            }

            #
            # Authorize and validate domains for this account
            #
            file delete -force [ns_server pagedir]/.well-known
            file mkdir [ns_server pagedir]/.well-known

            foreach domain ${:domains} {
                set status [:authorizeDomain $domain]
                if {$status eq "invalid"} {
                    ns_write [subst {
                        Validation of domain $domain failed.
                        <p>Please restart the procedure at <a href="${:startUrl}">${:startUrl}</a>
                    }]
                    return
                }
            }

            file delete -force [ns_server pagedir]/.well-known


            #
            # Get certificate
            #
            set status [:certificateRequest]
            if {$status >= 400} {
                :abortMsg $status "Certificate request"
                return
            }

            #
            # Install certificate and update configuration
            #
            :certificateInstall
            :updateConfiguration

            ns_write [subst {<br>
                To use the new certificate, restart your NaviServer instance
                and check results on <a href="https://${:domain}">https://${:domain}</a>.
                <p>
            }]
        }
    }
}

# Check user access if configured
if { ($enabled == 0 && [ns_conn peeraddr] ni {"127.0.0.1" "::1"}) ||
     ($user ne "" && ([ns_conn authuser] ne $user || [ns_conn authpassword] ne $password)) } {
    ns_returnunauthorized
    return
}

# Produce page
ns_set update [ns_conn outputheaders] "Expires" "now"

set c [::letsencrypt::Client new]
$c getCertificate
$c destroy

#
# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:
