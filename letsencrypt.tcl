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
            Please enter the domain names for the SSL certificate:<br>
            <input name="domains" size="80">
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

    nsf::proc readFile {{-binary:switch f} fileName} {
        set F [open $fileName r]
        if {$binary} { fconfigure $F -translation binary }
        set content [read $F]
        close $F
        return $content
    }

    nsf::proc writeFile {{-binary:switch f} {-append:switch f} fileName content} {
        set mode [expr {$append ? "a" : "w"}]
        set F [open $fileName $mode]
        if {$binary} { fconfigure $F -translation binary }
        puts -nonewline $F $content
        close $F
    }

    # ################################# #
    # ----- produce backup files -----  #
    # ################################# #

    nsf::proc backup {{-mode rename} fileName} {
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
                ns_write "Make backup of $fileName"
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

        ns_log notice "jwsignature payload:\n$payload\njws:\n$jws"
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

        #ns_log notice  "status: $S"
        #ns_log notice  "result: $R"
        #ns_log notice  "replyheaders:"
        #ns_log notice  [ns_set array $replyHeaders]

        # return status, result and replyheaders in a list
        return [list $S $R $replyHeaders]
    }

    # ########################## #
    # ----- MAIN PROCEDURE ----- #
    # ########################## #
    proc getCertificate {} {

        set domain [ns_queryget domains]

        # if a domain name was already submitted in the form,
        # a link is provided to the user to start the main procedure
        if {$domains eq ""} {
            domainForm
            return
        }

        set domain [lindex $domains 0]
        set sans   [lrange $domains 1 end]

        set starturl "[ns_conn proto]://$domain[ns_conn url]"

        set config {
            staging    {url https://acme-staging.api.letsencrypt.org/directory}
            production {url https://acme-v01.api.letsencrypt.org/directory}
        }

        ns_headers 200 text/html
        ns_write "<h3>Obtaining a certificate from Let's Encrypt using \
                  the [string totitle $::letsencrypt::API] API:</h3>"

        # ################################### #
        # ----- get urls from directory ----- #
        # ################################### #

        set url [dict get $config $::letsencrypt::API url]

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

        #
        # Repeat max 10 times until registration was successful
        #
        for {set count 0} {$count < 10} {incr count} {
            set rsa_key [pki::rsa::generate 2048]
            set modulus  [base64url [::pki::_dec_to_ascii [dict get $rsa_key n]]]
            set exponent [base64url [::pki::_dec_to_ascii [dict get $rsa_key e]]]

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
            ns_write "Registration ended with error $status<br>"
            ns_write "[printHeaders $replyHeaders]<br>$text<br>"
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
        ns_log notice  "AUTHORIZATION:"

        foreach d $domains {
            ns_write "<br>Authorizing account for domain <strong>$d</strong>... "

            set nonce [ns_set get $replyHeaders "replay-nonce"]
            set payload [subst {{"resource": "new-authz", "identifier": {"type": "dns", "value": "$d"}}}]

            set jws [jwsignature $rsa_key $modulus $exponent $nonce $payload]
            lassign [postRequest $jws $new_authz] httpStatus result replyHeaders
            ns_write "returned HTTP status $httpStatus<br>"

            # ##################### #
            # ----- challenge ----- #
            # ##################### #
            ns_write "... getting HTTP challenge... "
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
            writeFile [ns_server pagedir]/.well-known/acme-challenge/$token $token.$thumbprint64

            set payload [subst {{"resource": "challenge", "keyAuthorization": "$token.$thumbprint64"}}]

            set jws [jwsignature $rsa_key $modulus $exponent $nonce $payload]
            lassign [postRequest $jws $url] httpStatus result replyHeaders
            ns_write "returned HTTP status $httpStatus<br>"

            # ###################### #
            # ----- validation ----- #
            # ###################### #
            ns_write "... validating the challenge... "
            ns_log notice  "VALIDATION:"

            set nonce [ns_set get $replyHeaders "replay-nonce"]
            regexp {^<(.*)>;rel="up"} [ns_set get $replyHeaders "link"] . url
            set status [dict get [json::json2dict $result] status]

            ns_write "status: $status<br>"
            #ns_write "<pre>$result</pre>[printHeaders $replyHeaders]<br>"

            # check until validation is finished
            while {$status eq "pending"} {
                ns_write "... retry after one second... "
                ns_sleep 1

                set id [ns_http queue $url]
                ns_http wait -status S -result R -headers $replyHeaders $id

                #ns_log notice  "status: $S"
                #ns_log notice  "result: $R"
                #ns_log notice  "replyheaders:"
                #ns_log notice  [ns_set array $replyHeaders]

                set status [dict get [json::json2dict $R] status]
                ns_write "status: $status<br>"
                if {$status ni {"valid" "pending"}} {
                    ns_write "<pre>$R</pre>[printHeaders $replyHeaders]<br>"
                    break
                }
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
        ns_write "<br>Generating RSA key pair for SSL certificate... "

        #
        # Make sure, the sslpath exists
        #
        file mkdir $::letsencrypt::sslpath

        #
        # Repeat max 10 times until certificate was successfully obtained
        #
        for {set count 0} {$count < 10} {incr count} {
            ns_log notice  "CERTIFICATE request:"

            set nonce [ns_set get $replyHeaders "replay-nonce"]
            set csrViaOpenSLL 1
            if {$csrViaOpenSLL} {
                set csrConfFile $::letsencrypt::sslpath/$domain.csr.conf
                set csrFile     $::letsencrypt::sslpath/$domain.csr
                set keyFile     $::letsencrypt::sslpath/$domain.key

                exec -ignorestderr openssl genrsa -out $keyFile 2048
                set privKey [readFile $keyFile]

                file copy -force /etc/ssl/openssl.cnf $csrConfFile
                if {[llength $sans] > 0} {
                    set altNames {}; foreach alt $sans {lappend altNames DNS:$alt}
                    writeFile -append $csrConfFile "\n\[SAN\]\nsubjectAltName=[join $altNames ,]\n"
                    set extensions [list -reqexts SAN -extensions SAN]
                } else {
                    set extensions {}
                }
                exec openssl req -new -sha256 -outform DER {*}$extensions \
                    -subj "/CN=$domain" -key $keyFile -config $csrConfFile -out $csrFile
                set csr [readFile -binary $::letsencrypt::sslpath/$domain.csr]

            } else {
                set cert_key [pki::rsa::generate 2048]
                set csr [pki::pkcs::create_csr $cert_key [list CN $domain] 0]
                set privKey [pki::key $cert_key]
            }
            set csr64 [base64url $csr]
            set payload [subst {{"resource": "new-cert", "csr": "$csr64", "authorizations": "$authorization"}}]
            ns_write "DONE<br>"

            ns_write "Getting the certificate for domain $domain, SANs $sans... "
            set jws [jwsignature $rsa_key $modulus $exponent $nonce $payload]
            lassign [postRequest $jws $new_cert] status result replyHeaders
            ns_write "returned HTTP status $status<br>"

            if {$status eq "400"} {
                ns_write "Certificate request failed. Generating new RSA key pair... "
                ns_log notice "CSR-Request returned 400\n"
                ns_write "[printHeaders $replyHeaders]<br>$result<br>"

            } else {
                break
            }
        }

        if {$status >= 400} {
            ns_write "Certificate request ended with error $status.<br>"
            ns_write "[printHeaders $replyHeaders]<br>$result<br>"
            return
        }

        # ############################### #
        # ----- generate certificate ---- #
        # ############################### #

        ns_write "<br>Generate the certificate under $::letsencrypt::sslpath...<br>"

        ns_log notice  "Storing certificate under $::letsencrypt::sslpath/$domain.cer"
        writeFile -binary $::letsencrypt::sslpath/$domain.cer $result

        puts "Converting the certificate to PEM format to $::letsencrypt::sslpath/$domain.crt"
        exec openssl x509 -inform der -in $::letsencrypt::sslpath/$domain.cer -out $::letsencrypt::sslpath/$domain.crt
        set cert [readFile $::letsencrypt::sslpath/$domain.crt]

        #
        # build certificate in the file system. Backup old file if necessary.
        #
        set pemFile $::letsencrypt::sslpath/$domain.pem
        backup $pemFile

        # Save certificate and private key in single file in directory
        # of nsssl module

        ns_log notice  "Combining certificate and private key to $pemFile"
        writeFile $pemFile "$cert$privKey"

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

        writeFile -append $pemFile $R


        # ############################### #
        # ----- Add DH parameters ------- #
        # ############################### #

        ns_write "Adding DH parameters to $pemFile (might take a while) ... "
        exec -ignorestderr -- openssl dhparam 2048 >> $pemFile 2> /dev/null
        ns_write " DONE<br><br>"

        ns_write "New certificate successfully installed in: <strong>$pemFile</strong><br><br>"

        # ############################### #
        # ----- Update configuration ---- #
        # ############################### #

        #
        # Make first a backup of old config file ...
        #
        set backupConfigFile [backup -mode copy [ns_info config]]

        #
        # ... and update config file by reading its content and update
        # it in memory before writing it back to disk.
        #
        ns_write "Checking the NaviServer config file: "
        set C [readFile [ns_info config]]
        set origConfig $C

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
      ns_param   certificate   $pemFile
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
        } elseif {![regexp "ns_param\\s+certificate\\s+$pemFile" $C]} {
            ns_write {... updating the certificate entry<br>}
            regsub -all {ns_param\s+certificate\s+[^\n]+} $C "ns_param   certificate   $pemFile" C
        }

        #
        # Rewrite config file only, when the content has changed
        #
        if {$origConfig ne $C} {
            writeFile [ns_info config] $C
            ns_write [subst {
                Updating NaviServer config file<br>
                Please check updated config file: <strong>[ns_info config]</strong>
                <br>and update it (if necessary)<p>
            }]
        } else {
            ns_write {No need to update the NaviServer config file.<br>}
        }

        ns_write [subst {<br>
            To use the updated configuration, restart your NaviServer instance
            and check results on <a href="https://$domain">https://$domain</a>.
            <p>
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
