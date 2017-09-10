#
# letsencrypt.tcl --
#
#   A small Let's Encrypt client for NaviServer implemented in Tcl.
#
#   To use it, set enabled to 1 and drop it somewhere under
#   NaviServer pageroot which is usually /usr/local/ns/pages and point
#   browser to it.
#
#
# If this pages needs to be restricted assign username and password
# here.
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
    # the production API to void these limits. In such cases, set the
    # following variable to 0.
    #
    set productionAPI 1
}

##########################################################################
#
#  ---- no configuation below this point ---------------------------------
#
##########################################################################

package require json
package require pki

namespace eval ::letsencrypt {
    
    # ####################### #
    # ----- domain form ----- #
    # ####################### #
    proc domainForm {} {
        ns_return 200 text/html [subst {
            <head>
            <title>Let's Encrypt Client</title>
            </head>
            <body>
            <form method='post' action='[ns_conn url]'>
            Please enter the domain name for the SSL certificate:<br>
            <input name="domain">
            <input type='submit' value='Submit'>
            </form>
            </body>
        }]
    }

    proc printHeaders {headers} {
        set result "<pre>"
        foreach {k v} [ns_set array $headers] {
            append result "   $k: $v\n"
        }
        append result "</pre>\n"
    }

    # ################################# #
    # ----- base64url converting -----  #
    # ################################# #
    proc base64url {data} {
        return [string map {+ - / _ = {} \n {}} [ns_base64encode $data]]
    }

    # ############################## #
    # ----- json web signature ----- #
    # ############################## #
    proc jwsignature {rsa_key modulus exponent nonce payload} {
        # generate json web key
        set jwk [subst {{
            "kty": "RSA",
            "n": "$modulus",
            "e": "$exponent"
        }}]

        # build protected header
        set protected [subst {{"nonce": "$nonce"}}]
        set protected64 [base64url $protected]

        # build payload and input for signature
        set payload64 [base64url $payload]
        set siginput [subst {$protected64.$payload64}]

        # build signature
        set signature [pki::sign $siginput $rsa_key sha256]
        set signature64 [base64url $signature]

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

        ns_log notice "payload:\n$payload\n"
        ns_log notice "jws:\n$jws\n"
        return $jws
    }

    # ######################## #
    # ----- post request ----- #
    # ######################## #
    proc postRequest {jws url} {
        # define HTTP headers
        set queryHeaders [ns_set create]
        set replyHeaders [ns_set create]
        ns_set update $queryHeaders "Content-type" "application/jose+json"

        # submit post request
        set id [ns_http queue -method POST -headers $queryHeaders -body $jws $url]
        ns_http wait -status S -result R -headers $replyHeaders $id

        ns_log notice  "status: $S"
        ns_log notice  "result: $R"
        ns_log notice  "replyheaders:"
        ns_log notice  [ns_set array $replyHeaders]

        # return status, result and replyheaders in a list
        return [list $S $R $replyHeaders]
    }

    # ########################## #
    # ----- MAIN PROCEDURE ----- #
    # ########################## #
    proc getCertificate {} {

        set domain [ns_queryget domain]

        # if a domain name was already submitted in the form,
        # a link is provided to the user to start the main procedure
        if {$domain eq ""} {
            domainForm
            return
        }
        set starturl "[ns_conn proto]://$domain[ns_conn url]"

        ns_headers 200 text/html
        ns_log notice  "----- START -----"

        # ################################### #
        # ----- get urls from directory ----- #
        # ################################### #
        ns_write "Fetching Let's Encrypt URLs from directory...<br>"

        #
        # Choose between production and staging API:
        #
        if {$::letsencrypt::productionAPI} {
            # production API:
            set url https://acme-v01.api.letsencrypt.org/directory
        } else {
            # staging API:
            set url https://acme-staging.api.letsencrypt.org/directory
        }

        set id [ns_http queue $url]
        ns_http wait -status S -result R $id

        set urls [json::json2dict $R]

        set key_change  [dict get $urls key-change]
        set new_authz   [dict get $urls new-authz]
        set new_cert    [dict get $urls new-cert]
        set new_reg     [dict get $urls new-reg]
        set revoke_cert [dict get $urls revoke-cert]

        ns_write [subst {<br>
            Let's Encrypt URLs:<br>
            <pre>   $key_change\n   $new_authz\n   $new_cert\n   $new_reg\n   $revoke_cert</pre>
        }]

        # ############################ #
        # ----- generate rsa key ----- #
        # ############################ #
        ns_write "Generating RSA key pair for Let's Encrypt account registration...<br>"

        # repeat until registration was successful
        while {1} {
            set rsa_key [pki::rsa::generate 2048]
            array set key $rsa_key

            set modulus [base64url [::pki::_dec_to_ascii $key(n)]]
            set exponent [base64url [::pki::_dec_to_ascii $key(e)]]

            # ##################### #
            # ----- get nonce ----- #
            # ##################### #
            set replyHeaders [ns_set create]
            set id [ns_http queue -method HEAD $new_reg]

            ns_http wait -status S -result R -headers $replyHeaders $id
            set nonce [ns_set get $replyHeaders "replay-nonce"]

            # ######################## #
            # ----- registration ----- #
            # ######################## #
            ns_write "Creating new registration...<br>"
            ns_log notice  "REGISTRATION:"

            set payload [subst {{"resource": "new-reg", "contact": \["mailto:admin@$domain"\]}}]

            set jws [jwsignature $rsa_key $modulus $exponent $nonce $payload]
            lassign [postRequest $jws $new_reg] status text replyHeaders

            if {$status eq "400"} {
                ns_write "Registration failed. Retry and generate new RSA key pair...<br>"
            } else {
                break
            }
        }
        ns_write "Registration ended with status $status.<br>"

        if {$status >= 400} {
            ns_write "Registration ended with error."
            ns_write "$text ns_write [printHeaders $replyHeaders] <br>"
            return
        }

        # ##################### #
        # ----- agreement ----- #
        # ##################### #
        ns_write "<br>Signing agreement... "
        ns_log notice  "AGREEMENT:"

        set nonce [ns_set get $replyHeaders "replay-nonce"]
        set location [ns_set get $replyHeaders "location"]

        # parse link for next step from reply headers
        foreach link [ns_set array $replyHeaders] {
            regexp {^<(.*)>;rel="terms-of-service"} $link . url
        }

        set payload [subst {{"resource": "reg", "agreement": "$url"}}]
        set jws [jwsignature $rsa_key $modulus $exponent $nonce $payload]
        lassign [postRequest $jws $location] httpStatus . replyHeaders
        ns_write "returned HTTP status $httpStatus<br>"

        # ######################### #
        # ----- authorization ----- #
        # ######################### #
        ns_write "Authorizing account... "
        ns_log notice  "AUTHORIZATION:"

        set nonce [ns_set get $replyHeaders "replay-nonce"]
        set payload [subst {{"resource": "new-authz", "identifier": {"type": "dns", "value": "$domain"}}}]

        set jws [jwsignature $rsa_key $modulus $exponent $nonce $payload]
        lassign [postRequest $jws $new_authz] httpStatus result replyHeaders
        ns_write "returned HTTP status $httpStatus<br>"

        # ##################### #
        # ----- challenge ----- #
        # ##################### #
        ns_write "Getting HTTP challenge... "
        ns_log notice  "CHALLENGE:"

        set nonce [ns_set get $replyHeaders "replay-nonce"]
        set authorization [ns_set get $replyHeaders "location"]
        set challenges [dict get [json::json2dict $result] challenges]

        # parse HTTP challenge
        foreach entry $challenges {
            if {[dict filter $entry value "http-01"] ne ""} {
                set url [dict get $entry uri]
                set token [dict get $entry token]
            }
        }

        # generate thumbprint
        set pk [subst {{"e":"$exponent","kty":"RSA","n":"$modulus"}}]
        set thumbprint [binary format H* [ns_md string -digest sha256 $pk]]
        set thumbprint64 [base64url $thumbprint]

        # provide HTTP resource to fulfill HTTP challenge
        file mkdir [ns_server pagedir]/.well-known/acme-challenge
        set F [open [ns_server pagedir]/.well-known/acme-challenge/$token w]
        puts $F $token.$thumbprint64
        close $F

        set payload [subst {{"resource": "challenge", "keyAuthorization": "$token.$thumbprint64"}}]

        set jws [jwsignature $rsa_key $modulus $exponent $nonce $payload]
        lassign [postRequest $jws $url] httpStatus result replyHeaders
        ns_write "returned HTTP status $httpStatus<br><br>"

        # ###################### #
        # ----- validation ----- #
        # ###################### #
        ns_write "Validating the challenge...<br>"
        ns_log notice  "VALIDATION:"

        set nonce [ns_set get $replyHeaders "replay-nonce"]
        regexp {^<(.*)>;rel="up"} [ns_set get $replyHeaders "link"] . url
        set status [dict get [json::json2dict $result] status]

        ns_write "Validation status: $status<br>"
        #ns_write "<pre>$result</pre>[printHeaders $replyHeaders]<br>"

        # check until validation is finished
        while {$status eq "pending"} {
            ns_write "Retry after one second....<br>"
            ns_sleep 1

            set id [ns_http queue $url]
            ns_http wait -status S -result R -headers $replyHeaders $id

            ns_log notice  "status: $S"
            ns_log notice  "result: $R"
            ns_log notice  "replyheaders:"
            ns_log notice  [ns_set array $replyHeaders]

            set status [dict get [json::json2dict $R] status]
            ns_write "Validation status: $status<br>"
            if {$status ne "valid"} {
                ns_write "<pre>$R</pre>[printHeaders $replyHeaders]<br>"
            }
        }

        file delete -force [ns_server pagedir]/.well-known

        if {$status eq "invalid"} {
            ns_write [subst {Validation failed. <p>Please restart the procedure at <a href="$starturl">$starturl</a>}]
            return
        }

        # ########################### #
        # ----- get certificate ----- #
        # ########################### #
        ns_write "Generating RSA key pair for SSL certificate... "

        # repeat until certificate was successfully obtained
        while {1} {
            ns_log notice  "CERTIFICATE:"

            set nonce [ns_set get $replyHeaders "replay-nonce"]
            set cert_key [pki::rsa::generate 2048]
            set csr [pki::pkcs::create_csr $cert_key [list CN $domain] 0]
            set csr64 [base64url $csr]
            set payload [subst {{"resource": "new-cert", "csr": "$csr64", "authorizations": "$authorization"}}]
            ns_write "DONE<br>"

            ns_write "Getting the certificate... "
            set jws [jwsignature $rsa_key $modulus $exponent $nonce $payload]
            lassign [postRequest $jws $new_cert] status result replyHeaders
            ns_write "returned HTTP status $status<br>"

            if {$status eq "400"} {
                ns_write "Certificate request failed. Generating new RSA key pair... "
            } else {
                break
            }
        }

        # ############################### #
        # ----- generate certificate ---- #
        # ############################### #

        ns_write "<br>Generate the certificate under $::letsencrypt::sslpath...<br>"
        file mkdir $::letsencrypt::sslpath

        ns_log notice  "Storing certificate under $::letsencrypt::sslpath/$domain.cer"
        set F [open $::letsencrypt::sslpath/$domain.cer w]
        fconfigure $F -translation binary
        puts -nonewline $F $result
        close $F

        puts "Converting the certificate to PEM format to $::letsencrypt::sslpath/$domain.crt"
        exec openssl x509 -inform der -in $::letsencrypt::sslpath/$domain.cer -out $::letsencrypt::sslpath/$domain.crt
        set F [open $::letsencrypt::sslpath/$domain.crt]
        set cert [read $F]
        close $F

        # save certificate and private key in single file in directory of nsssl module
        ns_log notice  "Combining certificate and private key to $::letsencrypt::sslpath/$domain.pem"
        set F [open $::letsencrypt::sslpath/$domain.pem w]
        puts -nonewline $F $cert
        puts -nonewline $F [pki::key $cert_key]
        close $F

        ns_log notice  "Deleting $domain.cer and $domain.crt under $::letsencrypt::sslpath/"
        file delete $::letsencrypt::sslpath/$domain.cer
        file delete $::letsencrypt::sslpath/$domain.crt

        #
        # get certificate chain
        #
        ns_write "Obtaining certificate chain ... "
        set id [ns_http queue https://letsencrypt.org/certs/letsencryptauthorityx3.pem.txt]
        ns_http wait -status S -result R $id
        ns_write "returned HTTP status $S<br>"
        
        set F [open $::letsencrypt::sslpath/$domain.pem a]
        puts -nonewline $F $R
        close $F
        
        # ############################### #
        # ----- Add DH parameters ------- #
        # ############################### #

        ns_write "Adding DH parameters to $::letsencrypt::sslpath/$domain.pem (might take a while) ... "
        exec -ignorestderr -- openssl dhparam 2048 >> $::letsencrypt::sslpath/$domain.pem
        ns_write " DONE<br><br>"

        ns_write "Certificate successfully installed in: <strong>$::letsencrypt::sslpath/$domain.pem</strong><br><br>"

        # ############################### #
        # ----- Produce backup ----- ---- #
        # ############################### #

        #
        # Produce backup of old config file and write updated config
        # file.  Add timestamp to name of backup file to avoid loosing
        # configurations on multiple runs.
        #
        set backupConfigFile [ns_info config].bak.[clock seconds]

        ns_write [subst {
            Make backup of old config file in: $backupConfigFile<br>
        }]
        file copy -force [ns_info config] $backupConfigFile

        # ############################### #
        # ----- Update configuration ---- #
        # ############################### #

        ns_write "Adapting config file to use the new certificate:<br>"
        set F [open [ns_info config]]
        set C [read $F]
        close $F

        #
        # Check, if nsssl module is already loaded
        #
        set nssslLoaded 0
        foreach d [ns_driver info] {
            if {[dict get $d protocol] eq "https"} {
                set nssslLoaded 1
            }
        }
        if {$nssslLoaded} {
            ns_write "The nsssl driver module is apparently already loaded."
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
      ns_param   certificate   $::letsencrypt::sslpath/$domain.pem
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
        } else {
            ns_write [subst {... updating the certificate in config file<br>}]
            regsub -all {ns_param\s+certificate\s+[^\n]+} $C "ns_param   certificate   $::letsencrypt::sslpath/$domain.pem" C
        }

        set F [open [ns_info config] w]
        puts -nonewline $F $C
        close $F

        ns_write [subst {<br>
            Please check updated config file: <strong>[ns_info config]</strong>
            <p>Update it if necessary and restart your NaviServer instance. <br>You should be able to browse to
            <a href="https://$domain">https://$domain</a> afterwards.
        }]
    }

    # register procedure for obtaining certificate
    #ns_register_proc GET $::letsencrypt::clientUrl ::letsencrypt::getCertificate
}

# Check user access if configured
if { ($enabled == 0 && [ns_conn peeraddr] ni {"127.0.0.1" "::1"}) ||
     ($user ne "" && ([ns_conn authuser] ne $user || [ns_conn authpassword] ne $password)) } {
    ns_returnunauthorized
    return
}

# Produce page
ns_set update [ns_conn outputheaders] "Expires" "now"
::letsencrypt::getCertificate


#
# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:
