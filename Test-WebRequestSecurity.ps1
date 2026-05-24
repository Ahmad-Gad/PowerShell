## Code Type: Function
## Decription: Scan the security headers from a specified URL and display the report with the required actions.
## Author: Ahmad Gad
## Contact Email: ahmad.gad@outlook.ie, ahmad.adel@jemmail.com
## Version: 1.1
## WebSite: https://github.com/Ahmad-Gad/PowerShell
## Date Format: DD/MM/YYYY
## Created On: 28/08/2021
## Updated On: 22/05/2026
## Minimum PowerShell Version: 5.1
## Minimum CLR Version: 4.0.30319.42000 
## PowerShell Core Supported: Yes
## For more details please execute the following command after you execute this script: Get-Help Test-WebRequestSecurity -Detailed;
## References:
##   OWSP HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
##   Revoked Certificate Website: https://revoked.grc.com
##  "https://tls13.1d.pw" #Testing website that supports only TLS 1.3
## Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002" -Name "Functions";
## Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002";

#region Types
Enum SecurityHeaderStatus
{
    Missing = 0
    ShouldNotExist = 1
    ValuesMissing = 2
    BadValues = 3
    NeedReevaluation = 4
    WorthReview = 5
};

Enum SecurityHeaderAction
{
    Add = 0
    Remove = 1
    Fix = 2
    StrictReview = 3
    Review = 4
};

Enum KeyExchangeAlgorithm
{
    None = 0
    RsaSign = 9216
    RsaKeyX = 41984
    ECDH_Ephemeral = 44550
    DiffieHellman = 43522
}

Class Header
{
    [String]$Key;
    [String]$Value;

    Header(){}

    Header([String]$key, [String]$value) {
        $this.Key = $key;
        $this.Value = $value;
    }
}

Class Details
{
    [String]$Name;
    [String]$Url;
    [String]$Notes;
    [String]$Description;
    [String]$ExpectedValues;

    Details(){}

    Details([String]$name, [String]$url, [String]$notes, [String]$description){
        $this.Name = $name;
        $this.Url = $url;
        $this.Notes = $notes;
        $this.Description = $description;
}

    Details([String]$name, [String]$url, [String]$notes, [String]$description, [String]$expectedValues){
        $this.Name = $name;
        $this.Url = $url;
        $this.Notes = $notes;
        $this.Description = $description;
        $this.ExpectedValues = $expectedValues;
}
}

Class SecurityHeader
{
    [String]$Header;

    [String]$Value;

    [Details[]]$MissingValues;

    [SecurityHeaderStatus]$Status;

    [SecurityHeaderAction]$RequiredAction;
    
    [String]$ExpectedValues;

    [String]$Url;

    [String]$Notes;

    [String]$Description;
};

Class SecurityProtocolConnectionResult
{
    [String]$Protocol;
    [Boolean]$IsSupported;
    [Boolean]$IsAuthenticated;
    [Boolean]$IsEncrypted;
    [Boolean]$IsSigned;
    [String]$CipherAlgorithm;
    [Int]$CipherStrength;
    [KeyExchangeAlgorithm]$KeyExchangeAlgorithm;
    [String]$HashAlgorithm;
    [Int]$KeyExchangeStrength;
}

Class Certificate 
{
    [String]$Subject;
    [String]$FriendlyName;
    [String]$SerialNumber;
    [String]$Thumbprint;
    [String]$Issuer;
    [String]$SignatureAlgorithm;
    [String]$KeyExchangeAlgorithm;
    [Int]$KeySize;
    [String[]]$DnsNameList;
    [DateTime]$IssueDate;
    [DateTime]$ExpiryDate;
    [Boolean]$Expired;
    [Boolean]$Revoked;
    [Boolean]$ValidDomain;
    [Boolean]$Valid;
    [Boolean]$IsSelfSigned;
}

Class Report
{
    [String]$Host;
    [Int]$Port;
    [String]$IpAddress;
    [String]$IP4Address;
    [Boolean]$DnsResolved;
    [Boolean]$PingSuccess;
    [Header[]]$Headers;
    [SecurityHeader[]]$SecurityHeaders;
    [SecurityProtocolConnectionResult[]]$SecurityProtocols;
    [Certificate]$Certificate;
}
#endregion Types

Function Test-WebRequestSecurity
{
    <#
      .SYNOPSIS
      	Test the specified URI or Web Response object against all the possible security vulnerabilities based on the returned HTTP Response.
      .DESCRIPTION
        Check all the headers and provide a list of recommendations if some needs to be removed, some are missing or some need to be fixed.
        Verify if the connection is secured.
        Test the secure connection and display a list of the supported/opened security protocols.
        Get some information about the certificate and verify if it is valid (not expired or revoked).
      .INPUTS
        The URI in string format or [System.Uri] type.
      .OUTPUTS
        Report
      .EXAMPLE
        Test-WebRequestSecurity -Uri "https://mysite.com";
      .EXAMPLE
        $report = Test-WebRequestSecurity -Uri "https://mysite.com";
      .EXAMPLE
        "https://mysite.com" | Test-WebRequestSecurity;
      .EXAMPLE
        $report = "https://mysite.com" | Test-WebRequestSecurity;
      .EXAMPLE
        $report = Test-WebRequestSecurity -Uri "https://mysite.com" -ShowErrors;
      .PARAMETER Uri
        Alias: U
        Data Type: Uri
        Mandatory: True
        Description: The input Url to scan.
        Example(s): https://mysite.com
        Default Value: N/A
        Notes: This is mandatory in case if the "WebResponse" parameter is not specified.
      .PARAMETER ShowErrors
        Alias: S
        Data Type: Switch
        Mandatory: False
        Description: Display the raised errors/exception if the HTTP request invokation failed.
        Example(s): N/A
        Default Value: N/A
        Notes: N/A.
    #>
    [CmdletBinding()]
    [OutputType([Report])]
    Param
    (
        [Parameter(Mandatory=$True, Position= 0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)][Alias("Input", "U", "URL")][Uri]$Uri,
        [Parameter(Mandatory=$False, Position= 1)][Alias("S")][Switch]$ShowErrors
        
    )

    If ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host -ForegroundColor Red "This script requires PowerShell version 5.1 or later!";
        Return $null;
    }

    #region Private Functions
    Function Get-CertificateCore {
    [CmdletBinding()]
    [OutputType([Report])]
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias("Input")]
        [Uri]$Uri,

        [Parameter(Mandatory=$False, Position=2)]
        [Alias("S")]
        [Switch]$ShowErrors,

        [Parameter(Mandatory=$False, Position=2)]
        [Alias("R")]
        [Report]$Report        
    )

        Function Get-CertDnsNames {
        Param(
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
        )
        
            [String[]]$names = @();

            ForEach ($ext in $Cert.Extensions) {
                if ($ext.Oid.Value -eq "2.5.29.17") {
                    $text = $ext.Format($true);
                    $regexMatches = [Regex]::Matches($text, "DNS Name=(?<name>[^\r\n,]+)");

                    foreach ($m in $regexMatches) {
                        $names += $m.Groups["name"].Value.Trim();
                    };
                };
            };

            if ($names.Count -eq 0) {
                $cn = [Regex]::Match($Cert.Subject, "CN\s*=\s*([^,]+)");
                if ($cn.Success) {
                    $names += $cn.Groups[1].Value.Trim();
                }
            }

            return @($names | Sort-Object -Unique);
        }

        Function Test-CertNameMatch {
            Param(
                [String]$HostName,
                [String[]]$DnsNames
            )

            $hostLower = $HostName.ToLowerInvariant();

            foreach ($name in $DnsNames) {
                $dns = $name.ToLowerInvariant();

                if ($dns -eq $hostLower) {
                    return $true;
                }

                if ($dns.StartsWith("*.")) {
                    $suffix = $dns.Substring(1);

                    if ($hostLower.EndsWith($suffix)) {
                        $prefix = $hostLower.Substring(0, $hostLower.Length - $suffix.Length);

                        if ($prefix -notmatch "\.") {
                            return $true;
                        }
                    }
                }
            }

            return $false;
        }

        $hostName = $Uri.Host;
        $port = $Uri.Port;

        if ($port -eq -1) {
            if ($Uri.Scheme -eq "https") {
                $port = 443;
            }
            else {
                $port = 80;
            }
        }

        if ($Uri.Scheme -ne "https") {
            Write-Host -ForegroundColor Red "Certificate retrieval requires an HTTPS Uri.";
            return $null;
        }

        $tcp = $null;
        $ssl = $null;
        $cert = $null;

        try {
            $tcp = [System.Net.Sockets.TcpClient]::new();
            $tcp.Connect($hostName, $port);

            $callback = [System.Net.Security.RemoteCertificateValidationCallback]{
                param($senderObject, $certificate, $chain, $sslPolicyErrors);
                return $true
            }

            $ssl = [System.Net.Security.SslStream]::new(
                $tcp.GetStream(),
                $false,
                $callback
            );

            $ssl.AuthenticateAsClient($hostName);

            if ($null -eq $ssl.RemoteCertificate) {
                return $null;
            }

            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate);
        }
        catch {
            if ($ShowErrors) {
                Write-Host -ForegroundColor Red "Failed to retrieve the certificate:";
                Write-Host -ForegroundColor Red "Error Message: $($_.Exception.Message)";
            }
            else {
                Write-Host -ForegroundColor Red "Failed to retrieve the certificate. Use '-ShowErrors' for more details.";
            }

            if ($null -ne $ssl) { 
                $ssl.Dispose(); 
            }
            if ($null -ne $tcp) { 
                $tcp.Dispose(); 
            }

            return $report;
        }

        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new();
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain;
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online;
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(30);
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority;

        $validChain = $chain.Build($cert);

        [Boolean]$revoked = $false;

        ForEach ($status in $chain.ChainStatus) {
            if (($status.Status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked) -ne 0) {
                $revoked = $true;
                break;
            }
        }

        $publicKey = $cert.PublicKey;

        [Certificate]$cerDetails = [Certificate]::new();

        $cerDetails.Revoked = $revoked;
        $cerDetails.DnsNameList = Get-CertDnsNames -Cert $cert;
        $cerDetails.IssueDate = $cert.NotBefore;
        $cerDetails.ExpiryDate = $cert.NotAfter;
        $cerDetails.Expired = (Get-Date) -ge $cert.NotAfter;
        $cerDetails.FriendlyName = $cert.FriendlyName;
        $cerDetails.Issuer = $cert.Issuer;
        $cerDetails.KeyExchangeAlgorithm = $publicKey.Oid.FriendlyName;

        try {
            $cerDetails.KeySize = $publicKey.Key.KeySize;
        }
        catch {
            $cerDetails.KeySize = 0;
        }

        $cerDetails.SerialNumber = $cert.SerialNumber;
        $cerDetails.Subject = $cert.Subject;
        $cerDetails.Thumbprint = $cert.Thumbprint;
        $cerDetails.SignatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName;
        $cerDetails.IsSelfSigned = $cerDetails.Subject -eq $cerDetails.Issuer -or $chain.ChainElements.Count -eq 1;
        $cerDetails.ValidDomain = Test-CertNameMatch -HostName $report.Host -DnsNames $cerDetails.DnsNameList;
        $cerDetails.Valid = $validChain -and $cerDetails.ValidDomain -and !$cerDetails.Expired -and !$cerDetails.Revoked;

        $chain.Dispose();
        $cert.Dispose();
        $ssl.Dispose();
        $tcp.Dispose();

        If ($null -ne $Report) {
            $Report.Host = $hostName;
            $Report.Port = $port;
            $Report.Certificate = $cerDetails;
            Return $Report;
        }
        Else {
            return $cerDetails;
        }
    }

    Function Get-SecurityHeaders
    {
        [CmdletBinding()]
        [OutputType([SecurityHeader[]])]
        Param
        (
            [Parameter(Mandatory=$True, Position= 0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)][Alias("Input", "H")][Header[]]$Headers
        )

        If ($null -eq $Headers -Or $Headers.Count -eq 0) {
            Return $null;
        }

        [String[]]$headersKey = $Headers | Select-Object Key -ExpandProperty Key;
        $cspHeaderName = "Content-Security-Policy";
        [String[]]$cspHeaderFullValues = @();
        $cspHeader = $Headers | Where-Object {$_.Key -eq $cspHeaderName};

        If ($null -ne $cspHeader)
        {
            $cspHeaderFullValues = $cspHeader.Value.Split(";");
        }

        $cspHeaderFlags = $cspHeaderFullValues | Select-Object @{Name = "Flag"; Expression={$_.Trim().Split(" ")[0].Trim()}} | Select-Object Flag -ExpandProperty Flag;

        $headersToRemove = $Headers | Where-Object {$_.Key -match "aspnet" -Or $_.Key -match "Powered-By" -Or $_.Key -eq "Server" -Or $_.Key -eq "X-Mod-Pagespeed" -Or $_.Key -eq "X-Pingback" -Or $_.Key -eq "X-XSS-Protection"};

        [Details[]]$requiredHeaders = [Details[]]@(
            #[Details]::New("", "", "", "", ""),
            #[Details]::New("Access-Control-Allow-Origin", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin", $null, "", "The Uri of the allowed origin and should not be '*'."),
            [Details]::New("X-Permitted-Cross-Domain-Policies", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Permitted-Cross-Domain-Policies", $null, "The X-Permitted-Cross-Domain-Policies header is a security feature that prevents external clients (like legacy Flash players or Adobe Acrobat) from interacting with your website's content and accessing sensitive data. It is used as a defense-in-depth measure to restrict unauthorized cross-domain requests and resource abuse.", "none"),
            [Details]::New("Expires", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Expires", $null, "The HTTP Expires response header contains the date/time after which the response is considered expired in the context of HTTP caching.", "0"),
            [Details]::New($cspHeaderName, "https://content-security-policy.com/", $null, "The HTTP Content Security Policy response header gives website admins a sense of control by giving them the authority to restrict the resources a user is allowed to load within site. In other words, you can whitelist your site’s content sources. Content Security Policy protects against Cross Site Scripting and other code injection attacks. Although it doesn’t eliminate their possibility entirely, it can sure minimize the damage. Compatibility isn’t a problem as most of the major browsers support CSP.", "frame-ancestors 'self'; default-src 'self'; object-src 'self'; script-src 'self';"),
            [Details]::New("Strict-Transport-Security","https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security", $null, "The HTTP Strict-Transport-Security response header (often abbreviated as HSTS) lets a web site tell browsers that it should only be accessed using HTTPS, instead of using HTTP.", "max-age=63072000; includeSubDomains; preload"),
            #[Details]::New("X-XSS-Protection", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection", $null, "The HTTP X-XSS-Protection response header is a feature of Internet Explorer, Chrome and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks. Although these protections are largely unnecessary in modern browsers when sites implement a strong Content-Security-Policy that disables the use of inline JavaScript ('unsafe-inline'), they can still provide protections for users of older web browsers that don't yet support CSP."),
            [Details]::New("X-Content-Type-Options", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options", "This header is used to block browsers' MIME type sniffing, which can transform non-executable MIME types into executable MIME types (MIME Confusion Attacks).", "The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in the Content-Type headers should not be changed and be followed. This is a way to opt out of MIME type sniffing, or, in other words, to say that the MIME types are deliberately configured.", "nosniff"),
            [Details]::New("Referrer-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy", "Referrer policy has been supported by browsers since 2014. Today, the default behavior in modern browsers is to no longer send all referrer information (origin, path, and query string) to the same site but to only send the origin to other sites. However, since not all users may be using the latest browsers we suggest forcing this behavior by sending this header on all responses.", "The Referrer-Policy HTTP header controls how much referrer information (sent via the Referer header) should be included with requests. Aside from the HTTP header, you can set this policy in HTML.", "strict-origin-when-cross-origin"),
            #[Details]::New("Feature-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Feature_Policy", "The header has now been renamed to 'Permissions-Policy'. However, it's better to keep both until the 'Permissions-Policy' is being recognized by all the browsers.", "The HTTP Feature-Policy header provides a mechanism to allow and deny the use of browser features in its own frame, and in content within any <iframe> elements in the document.", "geolocation=(), camera=(), microphone=()"),
            [Details]::New("Permissions-Policy", "https://www.w3.org/TR/permissions-policy-1/", "It is recommended to set it and disable all the features that your site does not need or allow them only to the authorized domains!", "Permissions Policy is a new header that allows a site to control which features and APIs can be used in the browser.", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(), accelerometer=(), autoplay=(), bluetooth=(), gyroscope=(), magnetometer=(), midi=(), screen-wake-lock=(), xr-spatial-tracking=()"),
            [Details]::New("Cache-Control", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses", "If the response contains sensitive data, and the browser is not instructed not to cache the contents, the sensitive data would be stored on the client disk and could be leaked!", "The HTTP Cache-Control header holds directives (instructions) in both requests and responses that control caching in browsers and shared caches (e.g., Proxies, CDNs).", "no-cache, no-store, must-revalidate"),
            [Details]::New("Content-Type", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type", "The Content-Type representation header is used to indicate the original media type of the resource (before any content encoding is applied for sending). If not set correctly, the resource (e.g. an image) may be interpreted as HTML, making XSS vulnerabilities possible.", "The HTTP Content-Type representation header is used to indicate the original media type of a resource before any content encoding is applied.", "text/html; charset=UTF-8"),
            [Details]::New("Cross-Origin-Opener-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy", "It is recommended to isolate the browsing context exclusively to same-origin documents.", "The HTTP Cross-Origin-Opener-Policy (COOP) response header allows a website to control whether a new top-level document, opened using Window.open() or by navigating to a new page, is opened in the same browsing context group (BCG) or in a new browsing context group.", "same-origin"),
            [Details]::New("Cross-Origin-Resource-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy", "It is recommended to limit current resource loading to the site and sub-domains only.", "The HTTP Cross-Origin-Resource-Policy response header indicates that the browser should block no-cors cross-origin or cross-site requests to the given resource.", "same-site"),
            [Details]::New("Cross-Origin-Embedder-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy", "It is recommended that a document can only load resources from the same origin, or resources explicitly marked as loadable from another origin.", "The HTTP Cross-Origin-Embedder-Policy (COEP) response header configures embedding cross-origin resources into the document.", "require-corp")
        );

        [Details[]]$requiredCspValues = [Details[]]@(
            [Details]::New("frame-ancestors", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors", "This CSP value obsoletes the 'X-Frame-Options' which may longer be supported by some browsers. So, even if the 'X-Frame-Options' exists, this value should be added to make sure it is supported by all the browsers.", "The HTTP Content-Security-Policy (CSP) frame-ancestors directive specifies valid parents that may embed a page using <frame>, <iframe>, <object>, <embed>, or <applet>.", "'none' or 'self'"),
            [Details]::New("default-src", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src", "The expected value should be either default-src 'self;' or default-src 'none';", "The HTTP Content-Security-Policy (CSP) default-src directive serves as a fallback for the other CSP fetch directives.", "'none' or 'self'"),
            [Details]::New("object-src", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src", "Elements controlled by object-src are perhaps coincidentally considered legacy HTML elements and aren't receiving new standardized features (such as the security attributes sandbox or allow for <iframe>). Therefore it is recommended to restrict this fetch-directive (e.g. explicitly set object-src 'none' if possible).", "The HTTP Content-Security-Policy object-src directive specifies valid sources for the <object>, <embed>, and <applet> elements.", "'none', 'self'"),
            [Details]::New("frame-src", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-src", $null, "The HTTP Content-Security-Policy (CSP) frame-src directive specifies valid sources for nested browsing contexts loading using elements such as <frame> and <iframe>.", "'none', 'self'"),
            [Details]::New("img-src", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/img-src", $null, "The HTTP Content-Security-Policy img-src directive specifies valid sources of images and favicons.", "'none', 'self'"),
            [Details]::New("font-src", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/font-src",$null, "The HTTP Content-Security-Policy (CSP) font-src directive specifies valid sources for fonts loaded using @font-face.", "'none', 'self'"),
            [Details]::New("script-src", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src", $null, "The HTTP Content-Security-Policy (CSP) script-src directive specifies valid sources for JavaScript. This includes not only URLs loaded directly into <script> elements, but also things like inline script event handlers (onclick) and XSLT stylesheets which can trigger script execution.", "'none', 'self', 'nonce-?????' or hash"),
            [Details]::New("style-src", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src", $null, "The HTTP Content-Security-Policy (CSP) style-src directive specifies valid sources for CSS styles. This includes not only URLs loaded directly into <style> elements, but also things like inline styles.", "'none', 'self', 'nonce-?????' or hash"),
            [Details]::New("Upgrade-Insecure-Requests", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Upgrade-Insecure-Requests", $null, "The Upgrade-Insecure-Requests directive in a Content Security Policy (CSP) tells the browser to automatically rewrite all HTTP URLs to HTTPS before making a request. It is vital for fixing mixed-content warnings, migrating legacy sites to HTTPS without manual URL updates, and protecting user data.")
        );

        [Details[]]$missingHeaders = $requiredHeaders | Where-Object {$_.Name -notin $headersKey};

        [SecurityHeader[]] $headersSummary = @();
        $headersToRemove | ForEach-Object {
            $securityHeader = [SecurityHeader]::New();
            $securityHeader.Header = $_.Key;
            $securityHeader.Status = [SecurityHeaderStatus]::ShouldNotExist;
            $securityHeader.RequiredAction = [SecurityHeaderAction]::Remove;
            $securityHeader.Description = "This header could expose some information about the used technology or the hosted server type which can make it more easier for hackers to focus their target on the designated technology/server.";
            $securityHeader.Value = $_.Value;
            $headersSummary += $securityHeader;
        };

        If ($null -ne $missingHeaders -And $missingHeaders.Count -gt 0) { 

            $missingHeaders | ForEach-Object {
                $securityHeader = [SecurityHeader]::New();
                $securityHeader.Header = $_.Name;
                $securityHeader.Url = $_.Url;
                $securityHeader.Notes = $_.Notes;
                $securityHeader.Status = [SecurityHeaderStatus]::Missing;
                $securityHeader.RequiredAction = [SecurityHeaderAction]::Add;
                $securityHeader.Description = $_.Description;
                $securityHeader.ExpectedValues = $_.ExpectedValues;
                If ($_.Name -eq $cspHeaderName)
                {
                    $securityHeader.MissingValues = $requiredCspValues;
                }

                $headersSummary += $securityHeader;
            };
        }  

        If ($cspHeaderFlags.Count -gt 0)
        {
            $missingCspHeaderValues = $requiredCspValues | Where-Object {$_.Name -notin $cspHeaderFlags};
            If ($null -ne $missingCspHeaderValues) {
                $cspHeaderDetails = $requiredHeaders | Where-Object {$_.Name -eq $cspHeaderName};
                $securityHeader = [SecurityHeader]::New();
                $securityHeader.Header = $cspHeaderDetails.Name;
                $securityHeader.Url = $cspHeaderDetails.Url;
                $securityHeader.Notes = $cspHeaderDetails.Notes;
                $securityHeader.Status = [SecurityHeaderStatus]::ValuesMissing;
                $securityHeader.RequiredAction = [SecurityHeaderAction]::Fix;
                $securityHeader.Description = $cspHeaderDetails.Description;
                $securityHeader.MissingValues = $missingCspHeaderValues;
                $securityHeader.Value = $cspHeader.Value;
                $securityHeader.ExpectedValues = $cspHeaderDetails.ExpectedValues;

                $headersSummary += $securityHeader;
            }  
        }

        $cspHeaderFullValues | ForEach-Object {
            $cspFlagName = $_.Trim().Split(" ")[0].Trim();

            If ($cspFlagName -ne [String]::Empty) {
                $eval = $_.Replace("""", "'");
                $cspFlagDetails = $requiredCspValues | Where-Object {$_.Name -eq $cspFlagName};

                If (![String]::IsNullOrWhiteSpace($cspFlagDetails.ExpectedValues)) {
                    If($eval -match "unsafe" -Or $eval -match "\*" -Or $eval -match "data:") {
                        $securityHeader = [SecurityHeader]::New();
                        $securityHeader.Header = "CSP:$cspFlagName";
                        $securityHeader.Url = $cspFlagDetails.Url;
                        $securityHeader.Notes = $cspFlagDetails.Notes;
                        $securityHeader.Status = [SecurityHeaderStatus]::BadValues;
                        $securityHeader.RequiredAction = [SecurityHeaderAction]::Fix;
                        $securityHeader.Description = $cspFlagDetails.Description;
                        $securityHeader.Value = $_;
                        $securityHeader.ExpectedValues = $cspFlagDetails.ExpectedValues;
                        $headersSummary += $securityHeader;
                    }
                    Else{
                        If ($eval -notmatch "'none'" -And $eval -notmatch "'self'" -And $eval -notmatch "'nonce-" -And $eval -notmatch "'sha256-" -And $eval -notmatch "'sha384" -And $eval -notmatch "'sha512") {
                            $securityHeader = [SecurityHeader]::New();
                            $securityHeader.Header = "CSP:$cspFlagName";
                            $securityHeader.Url = $cspFlagDetails.Url;
                            $securityHeader.Notes = $cspFlagDetails.Notes;
                            $securityHeader.Status = [SecurityHeaderStatus]::NeedReevaluation;
                            $securityHeader.RequiredAction = [SecurityHeaderAction]::StrictReview;
                            $securityHeader.Description = $cspFlagDetails.Description;
                            $securityHeader.Value = $_;
                            $securityHeader.ExpectedValues = $cspFlagDetails.ExpectedValues;
                            $headersSummary += $securityHeader;
                        }
                    } 
                }
            }
        }

        Return $headersSummary;
    }

    Function Get-Certificate
    {
        [CmdletBinding()]
        [OutputType([Report])]
        Param
        (
            [Parameter(Mandatory=$True, Position= 0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)][Alias("Input")][Uri]$Uri,
            [Parameter(Mandatory=$False, Position= 2)][Alias("S")][Switch]$ShowErrors,
            [Parameter(Mandatory=$False, Position= 3)][Alias("R")][Report]$Report
        )

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
        [System.Net.HttpWebResponse]$res = $null;
        Try
        {
            [System.Net.WebRequest]$webRequest = [System.Net.WebRequest]::Create($Uri);
            $res = $webRequest.GetResponse();
        }
        Catch
        {
            If ($ShowErrors)
            {
                $ErrorMessage = $_.Exception.Message;
                Write-Host -ForegroundColor Red "Failed to invoke the HTTP request for the specified Uri with the following error:";
                Write-Host -ForegroundColor Red "Error Message: $ErrorMessage";
            }
            Else
            {
                Write-Host -ForegroundColor Red "Failed to invoke the HTTP request for the specified Uri. For more details about the error, please use the '-ShowErrors' parameter/switch!";
            }
            
            If ($null -ne $res) {
                $res.Dispose();
            }
            
            Return $null;
        }
        
        If ($null -eq $res)
        {
            Write-Host -ForegroundColor Red "Failed to connect to the specified web site.";
            Return $null;
        }

        If ($null -eq $report) {
            $report = [Report]::New();
        }

        If ($null -ne $res.Headers -And $res.Headers.Count -gt 0)
        {
            [Header[]]$headers = @();
            $res.Headers.Keys | ForEach-Object {
                $header = [Header]::New($_, $res.Headers[$_]);
                $headers += $header;
            };

            $report.Headers = $headers;
        }

        $cert = $webRequest.ServicePoint.Certificate;

        $report.Host = $webRequest.Address.Host;
        $report.Port = $webRequest.Address.Port;
        If ($null -eq $cert) 
        {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$null};
            $res.Dispose();
            Return $null;
        }

        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain;
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain;
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online;
        $chain.ChainPolicy.UrlRetrievalTimeout = New-Object System.TimeSpan(0, 0, 30);
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority;
        $valid = $chain.Build($cert);

        $revoked = $chain.ChainStatus.Status -eq "Revoked";
        $chainCert = $chain.ChainElements[0].Certificate;
        $publicKey = $chainCert.PublicKey;
        [Certificate]$cerDetails = [Certificate]::New();

        $cerDetails.Revoked = $revoked;
        $cerDetails.DnsNameList = $chainCert.DnsNameList | Select-Object Unicode -ExpandProperty Unicode;
        $cerDetails.IssueDate = $chainCert.NotBefore;
        $cerDetails.ExpiryDate = $chainCert.NotAfter;
        $cerDetails.Expired = (Get-Date) -ge $chainCert.NotAfter;
   
        $cerDetails.FriendlyName = $chainCert.FriendlyName;
        $cerDetails.Issuer = $chainCert.Issuer;
        $cerDetails.KeyExchangeAlgorithm = $publicKey.Oid.FriendlyName;
        $cerDetails.KeySize = $publicKey.Key.KeySize;
        $cerDetails.SerialNumber = $chainCert.SerialNumber;
        $cerDetails.Subject = $chainCert.Subject;
        $cerDetails.Thumbprint = $chainCert.Thumbprint;
        $cerDetails.SignatureAlgorithm = $chainCert.SignatureAlgorithm.FriendlyName;
        $cerDetails.IsSelfSigned = $cerDetails.Subject -eq $cerDetails.Issuer -Or $chain.ChainElements.Count -eq 1;
        
        [Boolean]$validDomain = $cerDetails.DnsNameList -contains $report.Host;

        If (!$validDomain) {
            [String[]]$domainSections = $report.Host.Split('.');
            If ($domainSections.Length -gt 2) {
                $domainSections[0] = "*";
                $wildCardDomain = $domainSections -Join '.';
                $validDomain = $cerDetails.DnsNameList -contains $wildCardDomain;
            }
        }

        $cerDetails.ValidDomain = $validDomain;
        $cerDetails.Valid = $valid -And $validDomain -And !$cerDetails.Expired;

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$null};
        $chain.Dispose();
        $res.Dispose();
        $report.Certificate = $cerDetails;
        Return $report;
    }

    Function Get-ResponseHeaders
    {
        [CmdletBinding()]
        [OutputType([Header[]])]
        Param
        (
            [Parameter(Mandatory=$True, Position= 0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)][Alias("Input")][Uri]$Uri,
            [Parameter(Mandatory=$False, Position= 2)][Alias("S")][Switch]$ShowErrors
        )

        Try
        {
            $rawHeaders = Invoke-WebRequest -Uri $Uri -SkipCertificateCheck -SkipHeaderValidation -SkipHttpErrorCheck | Select-Object Headers -ExpandProperty Headers;
        }
        Catch
        {
            If ($ShowErrors)
            {
                $ErrorMessage = $_.Exception.Message;
                Write-Host -ForegroundColor Red "Failed to invoke the HTTP request for the specified Uri with the following error:";
                Write-Host -ForegroundColor Red "Error Message: $ErrorMessage";
            }
            Else
            {
                Write-Host -ForegroundColor Red "Failed to invoke the HTTP request for the specified Uri. For more details about the error, please use the '-ShowErrors' parameter/switch!";
            }
            
            If ($null -ne $res) {
                $res.Dispose();
            }
            
            Return $null;
        }
        
        If ($null -eq $rawHeaders -Or $rawHeaders.Count -eq 0)
        {
            Write-Host -ForegroundColor Red "Failed to get the headers of the specified Uri.";
            Return $null;
        }

        [Header[]]$headers = @();
        $rawHeaders.Keys | ForEach-Object {
            $key = $_;
            $value = $rawHeaders[$_][0];
            $header = [Header]::New($key, $value);
            $headers += $header;
        };

        Return $headers;
    }

    Function Get-SecurityProtocols
    {
        [CmdletBinding()]
        [OutputType("[SecurityProtocolConnectionResult[]]")]
        Param
        (
            [Parameter(Mandatory=$True, Position= 0)][Alias("H")][String]$HostName,
            [Parameter(Mandatory=$True, Position= 1)][Alias("P")][Int]$Port
        )

        [System.Security.Authentication.SslProtocols[]]$sps = @(
            [System.Security.Authentication.SslProtocols]::Ssl2,
            [System.Security.Authentication.SslProtocols]::Ssl3,
            [System.Security.Authentication.SslProtocols]::Tls,
            [System.Security.Authentication.SslProtocols]::Tls11,
            [System.Security.Authentication.SslProtocols]::Tls12,
            [System.Security.Authentication.SslProtocols]::Tls13
        );

        [SecurityProtocolConnectionResult[]]$list = @();

        ForEach($sp in $sps) 
        {
            [SecurityProtocolConnectionResult]$spcr = [SecurityProtocolConnectionResult]::New();
            [System.Net.Security.SslStream]$sslStream = $null;
            [System.Net.Sockets.TcpClient]$tcpClient = $null;
            Try
            {
                $tcpClient = New-Object System.Net.Sockets.TcpClient;
                $TcpClient.Connect($HostName, $Port);
                $sslStream = New-Object System.Net.Security.SslStream $TcpClient.GetStream(), $true, ([System.Net.Security.RemoteCertificateValidationCallback]{ $True });
                $sslStream.ReadTimeout = 15000;
                $sslStream.WriteTimeout = 15000;
                $sslStream.AuthenticateAsClient($HostName, $null, $sp, $False);
                $spcr.IsSupported = $True;
                $spcr.CipherAlgorithm = $sslStream.CipherAlgorithm;
                $spcr.CipherStrength = $sslStream.CipherStrength;
                $spcr.HashAlgorithm = $sslStream.HashAlgorithm;
                $spcr.IsAuthenticated = $sslStream.IsAuthenticated;
                $spcr.IsEncrypted = $sslStream.IsEncrypted;
                $spcr.IsSigned = $sslStream.IsSigned;
                $spcr.KeyExchangeAlgorithm = $sslStream.KeyExchangeAlgorithm;
                $spcr.KeyExchangeStrength = $sslStream.KeyExchangeStrength;
            }
            Catch
            {
            }

   
            If ($null -ne $sslStream) {
                $sslStream.Dispose();
            }

            If ($null -ne $tcpClient) {
                $tcpClient.Dispose();
            }

            $spcr.Protocol = $sp;
            $list += $spcr;
        }

        Return $list;
    }
    #endregion Private Functions

    $Error.Clear();
    [Report]$report = New-Object Report;
    $ping = Test-Connection $Uri.Host -Count 1 -ErrorAction SilentlyContinue;
    $report.PingSuccess = $null -ne $ping -And $ping.Status -eq [System.Net.NetworkInformation.IPStatus]::Success;
    $dns = Resolve-DnsName -Name $Uri.Host -ErrorAction SilentlyContinue;
    
    if ($null -ne $dns) {
        $dnsItem = ($dns | Where-Object {$_.Type -eq 1})[0];
        $report.DnsResolved = $true;
        $report.IpAddress = $dnsItem.IPAddress;
        $report.IP4Address = $dns.IP4Address;
    }
    else {
        $report.DnsResolved = $false;
    }

    $report.Host = $Uri.Host;
    $report.Port = $Uri.Port;

    If ($PSVersionTable.PSEdition -eq "Core") {
        $report.Headers = Get-ResponseHeaders -Uri $Uri -ShowErrors:$ShowErrors;
        $certificate = Get-CertificateCore -Uri $Uri -ShowErrors:$ShowErrors;
        $report.Certificate = $certificate;
    }
    Else {
        $report = Get-Certificate -Uri $Uri -ShowErrors:$ShowErrors -Report $report;
    }

    If($null -ne $report.Headers) {
        [SecurityHeader[]]$securityHeaders = Get-SecurityHeaders -Headers $report.Headers;
        $report.SecurityHeaders = $securityHeaders;
    }
  
    [SecurityProtocolConnectionResult[]] $sprsList = Get-SecurityProtocols -HostName $report.Host -Port $report.Port;
    $report.SecurityProtocols = $sprsList;

    Return $report;
}