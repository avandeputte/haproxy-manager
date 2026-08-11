// Visit every entry in the navigation and fail if a page reports a name it
// does not have.
//
// route() catches whatever a renderer throws and prints the message into the
// page, which is why a missing import showed up as "E is not defined" on screen
// rather than as a crash. So this looks at what was rendered, and only treats
// ReferenceErrors as failures: thin stub data legitimately produces TypeErrors.
import "./stub-dom.mjs";

// Plausible answers, so a page that fails is failing on its own account and
// not because the stub handed it nothing. Anything unlisted gets an empty
// list for a collection and an empty object otherwise.
// Captured from a running node, so the shapes cannot drift away from the
// API. Regenerate with tools/uitests/capture-fixtures.sh.
const FIXTURES = {
  "acme/cover": {
    "error": "host is required",
    "ok": false
  },
  "acme/dnsapi": {
    "acme_home": "/var/lib/acme.sh",
    "count": 191,
    "hooks": [
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_1984hosting",
        "hook": "dns_1984hosting",
        "options": [
          {
            "desc": "Username",
            "name": "One984HOSTING_Username",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "One984HOSTING_Password",
            "optional": false
          },
          {
            "desc": "Base32 TOTP shared secret. Required only if the account has 2FA enabled. Requires oathtool. Used to mint the OTP code automatically at login so cron renewals keep working.",
            "name": "One984HOSTING_TOTP_Secret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "1984.hosting",
        "title": "1984.hosting"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_acmedns",
        "hook": "dns_acmedns",
        "options": [
          {
            "desc": "Username. Optional.",
            "name": "ACMEDNS_USERNAME",
            "optional": true
          },
          {
            "desc": "Password. Optional.",
            "name": "ACMEDNS_PASSWORD",
            "optional": true
          },
          {
            "desc": "Subdomain. Optional.",
            "name": "ACMEDNS_SUBDOMAIN",
            "optional": true
          },
          {
            "desc": "API endpoint. Default: \"https://auth.acme-dns.io\".",
            "name": "ACMEDNS_BASE_URL",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "github.com/joohoi/acme-dns",
        "title": "acme-dns Server API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_acmeproxy",
        "hook": "dns_acmeproxy",
        "options": [
          {
            "desc": "API Endpoint",
            "name": "ACMEPROXY_ENDPOINT",
            "optional": false
          },
          {
            "desc": "Username",
            "name": "ACMEPROXY_USERNAME",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "ACMEPROXY_PASSWORD",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "github.com/mdbraber/acmeproxy",
        "title": "AcmeProxy Server API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_active24",
        "hook": "dns_active24",
        "options": [
          {
            "desc": "API Key. Called \"Identifier\" in the Active24 Admin",
            "name": "Active24_ApiKey",
            "optional": false
          },
          {
            "desc": "API Secret. Called \"Secret key\" in the Active24 Admin",
            "name": "Active24_ApiSecret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Active24.cz",
        "title": "Active24.cz"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_edgedns",
        "hook": "dns_edgedns",
        "options": [
          {
            "desc": "Host",
            "name": "AKAMAI_HOST",
            "optional": false
          },
          {
            "desc": "Access token",
            "name": "AKAMAI_ACCESS_TOKEN",
            "optional": false
          },
          {
            "desc": "Client token",
            "name": "AKAMAI_CLIENT_TOKEN",
            "optional": false
          },
          {
            "desc": "Client secret",
            "name": "AKAMAI_CLIENT_SECRET",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "techdocs.Akamai.com/edge-dns/reference/edge-dns-api",
        "title": "Akamai.com Edge DNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_ali",
        "hook": "dns_ali",
        "options": [
          {
            "desc": "API Key",
            "name": "Ali_Key",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "Ali_Secret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "AlibabaCloud.com",
        "title": "AlibabaCloud.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_kas",
        "hook": "dns_kas",
        "options": [
          {
            "desc": "API login name",
            "name": "KAS_Login",
            "optional": false
          },
          {
            "desc": "API auth type. Default: \"plain\"",
            "name": "KAS_Authtype",
            "optional": false
          },
          {
            "desc": "API auth data",
            "name": "KAS_Authdata",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "kas.all-inkl.com",
        "title": "All-inkl Kas Server"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_alviy",
        "hook": "dns_alviy",
        "options": [
          {
            "desc": "API token. Get it from the https://cloud.alviy.com/token",
            "name": "Alviy_token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Alviy.com",
        "title": "Alviy.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_ad",
        "hook": "dns_ad",
        "options": [
          {
            "desc": "API Key",
            "name": "AD_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "AlwaysData.com",
        "title": "AlwaysData.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_aws",
        "hook": "dns_aws",
        "options": [
          {
            "desc": "API Key ID",
            "name": "AWS_ACCESS_KEY_ID",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "AWS_SECRET_ACCESS_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "docs.aws.amazon.com/route53/",
        "title": "Amazon AWS Route53 domain API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_anx",
        "hook": "dns_anx",
        "options": [
          {
            "desc": "API Token",
            "name": "ANX_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Anexia.com",
        "title": "Anexia.com CloudDNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_artfiles",
        "hook": "dns_artfiles",
        "options": [
          {
            "desc": "API Username",
            "name": "AF_API_USERNAME",
            "optional": false
          },
          {
            "desc": "API Password",
            "name": "AF_API_PASSWORD",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ArtFiles.de",
        "title": "ArtFiles.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_arubabusiness",
        "hook": "dns_arubabusiness",
        "options": [
          {
            "desc": "Your ArubaBusiness API Key",
            "name": "AB_Key",
            "optional": false
          },
          {
            "desc": "Your account user",
            "name": "AB_User",
            "optional": false
          },
          {
            "desc": "Your account password",
            "name": "AB_Pass",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "business.aruba.it",
        "title": "ArubaBusiness"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_arvan",
        "hook": "dns_arvan",
        "options": [
          {
            "desc": "API Token",
            "name": "Arvan_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ArvanCloud.ir",
        "title": "ArvanCloud.ir"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_azion",
        "hook": "dns_azion",
        "options": [
          {
            "desc": "Email",
            "name": "AZION_Email",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "AZION_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Azion.com",
        "title": "Azion.om"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_azure",
        "hook": "dns_azure",
        "options": [
          {
            "desc": "Subscription ID",
            "name": "AZUREDNS_SUBSCRIPTIONID",
            "optional": false
          },
          {
            "desc": "Tenant ID",
            "name": "AZUREDNS_TENANTID",
            "optional": false
          },
          {
            "desc": "App ID. App ID of the service principal",
            "name": "AZUREDNS_APPID",
            "optional": false
          },
          {
            "desc": "Client Secret. Secret from creating the service principal",
            "name": "AZUREDNS_CLIENTSECRET",
            "optional": false
          },
          {
            "desc": "Use Managed Identity. Use Managed Identity assigned to a resource instead of a service principal. \"true\"/\"false\"",
            "name": "AZUREDNS_MANAGEDIDENTITY",
            "optional": false
          },
          {
            "desc": "Bearer Token. Used instead of service principal credentials or managed identity. Optional.",
            "name": "AZUREDNS_BEARERTOKEN",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "Azure.microsoft.com",
        "title": "Azure"
      },
      {
        "docs": "https://cloud.baidu.com/doc/BCD/",
        "hook": "dns_baidu",
        "options": [
          {
            "desc": "AccessKeyId",
            "name": "Baidu_AK",
            "optional": false
          },
          {
            "desc": "SecretAccessKey",
            "name": "Baidu_SK",
            "optional": false
          }
        ],
        "options_alt": [
          {
            "desc": "API host, default: bcd.baidubce.com",
            "name": "Baidu_BCD_Host",
            "optional": false
          },
          {
            "desc": "New DNS API host, default: dns.baidubce.com",
            "name": "Baidu_DNS_Host",
            "optional": false
          },
          {
            "desc": "Engine preference, default: auto",
            "name": "Baidu_API_Preference",
            "optional": false
          },
          {
            "desc": "API version number, default: 1",
            "name": "Baidu_BCD_Version",
            "optional": false
          },
          {
            "desc": "Signature expiration seconds, default: 3600",
            "name": "Baidu_BCD_Expire",
            "optional": false
          },
          {
            "desc": "Resolve view, default: DEFAULT",
            "name": "Baidu_View",
            "optional": false
          },
          {
            "desc": "New DNS line, default: default",
            "name": "Baidu_Line",
            "optional": false
          },
          {
            "desc": "Resolve ttl seconds, default: 300",
            "name": "Baidu_TTL",
            "optional": false
          },
          {
            "desc": "Max records to delete in one run, default: 20",
            "name": "Baidu_RM_Max",
            "optional": false
          }
        ],
        "site": "cloud.baidu.com",
        "title": "Baidu Cloud BCD DNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_beget",
        "hook": "dns_beget",
        "options": [
          {
            "desc": "API user",
            "name": "BEGET_User",
            "optional": false
          },
          {
            "desc": "API password",
            "name": "BEGET_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Beget.com",
        "title": "Beget.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_bh",
        "hook": "dns_bh",
        "options": [
          {
            "desc": "API User identifier.",
            "name": "BH_API_USER",
            "optional": false
          },
          {
            "desc": "API Secret key.",
            "name": "BH_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "best-hosting.cz",
        "title": "Best-Hosting.cz"
      },
      {
        "docs": "https://github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_bhosted",
        "hook": "dns_bhosted",
        "options": [
          {
            "desc": "API username",
            "name": "BHOSTED_Username",
            "optional": false
          },
          {
            "desc": "API password (MD5 hash like bHosted web services example)",
            "name": "BHOSTED_Password",
            "optional": false
          },
          {
            "desc": "TTL for TXT record (default: 300)",
            "name": "BHOSTED_TTL",
            "optional": false
          },
          {
            "desc": "Optional override (useful for multi-part TLDs like co.uk)",
            "name": "BHOSTED_SLD",
            "optional": true
          },
          {
            "desc": "Optional override (useful for multi-part TLDs like co.uk)",
            "name": "BHOSTED_TLD",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "bHosted.nl",
        "title": "bHosted.nl DNS API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_bookmyname",
        "hook": "dns_bookmyname",
        "options": [
          {
            "desc": "Username",
            "name": "BOOKMYNAME_USERNAME",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "BOOKMYNAME_PASSWORD",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "BookMyName.com",
        "title": "BookMyName.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_bunny",
        "hook": "dns_bunny",
        "options": [
          {
            "desc": "API Key",
            "name": "BUNNY_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Bunny.net/dns/",
        "title": "Bunny.net"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_calrissia",
        "hook": "dns_calrissia",
        "options": [
          {
            "desc": "Personal access token",
            "name": "CALRISSIA_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "calrissia.be",
        "title": "Calrissia.be DNS API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cdmon",
        "hook": "dns_cdmon",
        "options": [
          {
            "desc": "API Key",
            "name": "CDMON_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "www.cdmon.com",
        "title": "cdmon"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cf",
        "hook": "dns_cf",
        "options": [
          {
            "desc": "API Key",
            "name": "CF_Key",
            "optional": false
          },
          {
            "desc": "Your account email",
            "name": "CF_Email",
            "optional": false
          }
        ],
        "options_alt": [
          {
            "desc": "API Token",
            "name": "CF_Token",
            "optional": false
          },
          {
            "desc": "Account ID",
            "name": "CF_Account_ID",
            "optional": false
          },
          {
            "desc": "Zone ID. Optional.",
            "name": "CF_Zone_ID",
            "optional": true
          }
        ],
        "site": "CloudFlare.com",
        "title": "CloudFlare"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cloudns",
        "hook": "dns_cloudns",
        "options": [
          {
            "desc": "Regular auth ID",
            "name": "CLOUDNS_AUTH_ID",
            "optional": false
          },
          {
            "desc": "Sub auth ID",
            "name": "CLOUDNS_SUB_AUTH_ID",
            "optional": false
          },
          {
            "desc": "Auth Password",
            "name": "CLOUDNS_AUTH_PASSWORD",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ClouDNS.net",
        "title": "ClouDNS.net"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_comlaude",
        "hook": "dns_comlaude",
        "options": [
          {
            "desc": "User account",
            "name": "COMLAUDE_USERNAME",
            "optional": false
          },
          {
            "desc": "User password",
            "name": "COMLAUDE_PASSWORD",
            "optional": false
          },
          {
            "desc": "generated API key",
            "name": "COMLAUDE_API_KEY",
            "optional": false
          },
          {
            "desc": "Group ID in comlaude user profile",
            "name": "COMLAUDE_GROUP_ID",
            "optional": false
          },
          {
            "desc": "it from the https://www.comlaude.com",
            "name": "Get",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "comlaude.com",
        "title": "comlaude.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_conoha",
        "hook": "dns_conoha",
        "options": [
          {
            "desc": "Username",
            "name": "CONOHA_Username",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "CONOHA_Password",
            "optional": false
          },
          {
            "desc": "TenantId",
            "name": "CONOHA_TenantId",
            "optional": false
          },
          {
            "desc": "Identity Service API. E.g. \"https://identity.xxxx.conoha.io/v2.0\"",
            "name": "CONOHA_IdentityServiceApi",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ConoHa.jp",
        "title": "ConoHa.jp"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_constellix",
        "hook": "dns_constellix",
        "options": [
          {
            "desc": "API Key",
            "name": "CONSTELLIX_Key",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "CONSTELLIX_Secret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Constellix.com",
        "title": "Constellix.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cn",
        "hook": "dns_cn",
        "options": [
          {
            "desc": "User",
            "name": "CN_User",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "CN_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "beta.api.Core-Networks.de/doc/",
        "title": "Core-Networks.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_cpanel",
        "hook": "dns_cpanel",
        "options": [
          {
            "desc": "Username",
            "name": "cPanel_Username",
            "optional": false
          },
          {
            "desc": "API Token",
            "name": "cPanel_Apitoken",
            "optional": false
          },
          {
            "desc": "Server URL. E.g. \"https://hostname:port\"",
            "name": "cPanel_Hostname",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "cPanel.net",
        "title": "cPanel Server API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_cpanel_uapi",
        "hook": "dns_cpanel_uapi",
        "options": [
          {
            "desc": "Username",
            "name": "cPanel_Username",
            "optional": false
          },
          {
            "desc": "API Token",
            "name": "cPanel_Apitoken",
            "optional": false
          },
          {
            "desc": "Server URL. E.g. \"https://hostname:port\"",
            "name": "cPanel_Hostname",
            "optional": false
          },
          {
            "desc": "optional TXT record TTL in seconds. Default: 120",
            "name": "cPanel_TTL",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "cpanel.net",
        "title": "cPanel UAPI"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_creoline",
        "hook": "dns_creoline",
        "options": [
          {
            "desc": "",
            "name": "creolineApiToken",
            "optional": false
          },
          {
            "desc": "",
            "name": "creolineApiSecret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "https://www.creoline.com/de",
        "title": "creoline"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_curanet",
        "hook": "dns_curanet",
        "options": [
          {
            "desc": "Auth ClientID. Requires scope dns",
            "name": "CURANET_AUTHCLIENTID",
            "optional": false
          },
          {
            "desc": "Auth Secret",
            "name": "CURANET_AUTHSECRET",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Curanet.dk",
        "title": "Curanet.dk"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_myapi",
        "hook": "dns_myapi",
        "options": [
          {
            "desc": "API Token. Get API Token from https://example.com/api/",
            "name": "MYAPI_Token",
            "optional": false
          },
          {
            "desc": "Option 2. Default \"default value\".",
            "name": "MYAPI_Variable2",
            "optional": false
          },
          {
            "desc": "Option 3. Optional.",
            "name": "MYAPI_Variable2",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "github.com/acmesh-official/acme.sh/wiki/DNS-API-Dev-Guide",
        "title": "Custom API Example"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cyon",
        "hook": "dns_cyon",
        "options": [
          {
            "desc": "Username",
            "name": "CY_Username",
            "optional": false
          },
          {
            "desc": "API Token",
            "name": "CY_Password",
            "optional": false
          },
          {
            "desc": "OTP token. Only required if using 2FA",
            "name": "CY_OTP_Secret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "cyon.ch",
        "title": "cyon.ch"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_ddnss",
        "hook": "dns_ddnss",
        "options": [
          {
            "desc": "API Token",
            "name": "DDNSS_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DDNSS.de",
        "title": "DDNSS.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_desec",
        "hook": "dns_desec",
        "options": [
          {
            "desc": "API Token",
            "name": "DEDYN_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "desec.readthedocs.io/en/latest/",
        "title": "deSEC.io"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_dgon",
        "hook": "dns_dgon",
        "options": [
          {
            "desc": "API Key",
            "name": "DO_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DigitalOcean.com/help/api/",
        "title": "DigitalOcean.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_da",
        "hook": "dns_da",
        "options": [
          {
            "desc": "API Server URL. E.g. \"https://remoteUser:remotePassword@da.domain.tld:8443\". Special characters in the user/password must be percent-encoded, e.g. \"@\" -> \"%40\".",
            "name": "DA_Api",
            "optional": false
          },
          {
            "desc": "Insecure TLS. 0: check for cert validity, 1: always accept",
            "name": "DA_Api_Insecure",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DirectAdmin.com/api.php",
        "title": "DirectAdmin Server API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_la",
        "hook": "dns_la",
        "options": [
          {
            "desc": "APIID",
            "name": "LA_Id",
            "optional": false
          },
          {
            "desc": "APISecret",
            "name": "LA_Sk",
            "optional": false
          },
          {
            "desc": "\u7528\u5192\u53f7\u8fde\u63a5 APIID APISecret \u518dbase64\u751f\u6210",
            "name": "LA_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "dns.la",
        "title": "dns.la"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_dnsservices",
        "hook": "dns_dnsservices",
        "options": [
          {
            "desc": "Username",
            "name": "DnsServices_Username",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "DnsServices_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DNS.Services",
        "title": "DNS.Services"
      },
      {
        "docs": "",
        "hook": "dns_czechia",
        "options": [
          {
            "desc": "Your API token from CZECHIA.COM/Zoner administration.",
            "name": "CZ_AuthorizationToken",
            "optional": false
          },
          {
            "desc": "Managed zones separated by comma or space (e.g. \"example.com\").",
            "name": "CZ_Zones",
            "optional": false
          },
          {
            "desc": "Defaults to https://api.czechia.com",
            "name": "CZ_API_BASE",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "",
        "title": "dns_czechia"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_dnsexit",
        "hook": "dns_dnsexit",
        "options": [
          {
            "desc": "API Key",
            "name": "DNSEXIT_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DNSExit.com",
        "title": "DNSExit.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_dnshome",
        "hook": "dns_dnshome",
        "options": [
          {
            "desc": "Subdomain",
            "name": "DNSHOME_Subdomain",
            "optional": false
          },
          {
            "desc": "Subdomain Password",
            "name": "DNSHOME_SubdomainPassword",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "dnsHome.de",
        "title": "dnsHome.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_dnsimple",
        "hook": "dns_dnsimple",
        "options": [
          {
            "desc": "OAuth Token",
            "name": "DNSimple_OAUTH_TOKEN",
            "optional": false
          },
          {
            "desc": "Account ID. Optional, only needed when the token can access multiple accounts.",
            "name": "DNSimple_ACCOUNT_ID",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "DNSimple.com",
        "title": "DNSimple.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_me",
        "hook": "dns_me",
        "options": [
          {
            "desc": "API Key",
            "name": "ME_Key",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "ME_Secret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DnsMadeEasy.com",
        "title": "DnsMadeEasy.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_dp",
        "hook": "dns_dp",
        "options": [
          {
            "desc": "Id",
            "name": "DP_Id",
            "optional": false
          },
          {
            "desc": "Key",
            "name": "DP_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DNSPod.cn",
        "title": "DNSPod.cn"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_dpi",
        "hook": "dns_dpi",
        "options": [
          {
            "desc": "Id",
            "name": "DPI_Id",
            "optional": false
          },
          {
            "desc": "Key",
            "name": "DPI_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DNSPod.com",
        "title": "DNSPod.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_doapi",
        "hook": "dns_doapi",
        "options": [
          {
            "desc": "LetsEncrypt Token",
            "name": "DO_LETOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "do.de",
        "title": "Domain-Offensive do.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_domeneshop",
        "hook": "dns_domeneshop",
        "options": [
          {
            "desc": "Token",
            "name": "DOMENESHOP_Token",
            "optional": false
          },
          {
            "desc": "Secret",
            "name": "DOMENESHOP_Secret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DomeneShop.no",
        "title": "DomeneShop.no"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_dreamhost",
        "hook": "dns_dreamhost",
        "options": [
          {
            "desc": "API Key",
            "name": "DH_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DreamHost.com",
        "title": "DreamHost.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_duckdns",
        "hook": "dns_duckdns",
        "options": [
          {
            "desc": "API Token",
            "name": "DuckDNS_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "www.DuckDNS.org",
        "title": "DuckDNS.org"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_durabledns",
        "hook": "dns_durabledns",
        "options": [
          {
            "desc": "API User",
            "name": "DD_API_User",
            "optional": false
          },
          {
            "desc": "API Key",
            "name": "DD_API_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DurableDNS.com",
        "title": "DurableDNS.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_dyn",
        "hook": "dns_dyn",
        "options": [
          {
            "desc": "Customer",
            "name": "DYN_Customer",
            "optional": false
          },
          {
            "desc": "API Username",
            "name": "DYN_Username",
            "optional": false
          },
          {
            "desc": "Secret",
            "name": "DYN_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Dyn.com",
        "title": "Dyn.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_df",
        "hook": "dns_df",
        "options": [
          {
            "desc": "Username",
            "name": "DF_user",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "DF_password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "DynDnsFree.de",
        "title": "DynDnsFree.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_dynu",
        "hook": "dns_dynu",
        "options": [
          {
            "desc": "Client ID",
            "name": "Dynu_ClientId",
            "optional": false
          },
          {
            "desc": "Secret",
            "name": "Dynu_Secret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Dynu.com",
        "title": "Dynu.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_dynv6",
        "hook": "dns_dynv6",
        "options": [
          {
            "desc": "REST API token. Get from https://DynV6.com/keys",
            "name": "DYNV6_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [
          {
            "desc": "Path to SSH private key file. E.g. \"/root/.ssh/dynv6\"",
            "name": "KEY",
            "optional": false
          }
        ],
        "site": "DynV6.com",
        "title": "DynV6.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_easydns",
        "hook": "dns_easydns",
        "options": [
          {
            "desc": "API Token",
            "name": "EASYDNS_Token",
            "optional": false
          },
          {
            "desc": "API Key",
            "name": "EASYDNS_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "easyDNS.net",
        "title": "easyDNS.net"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_edgecenter",
        "hook": "dns_edgecenter",
        "options": [
          {
            "desc": "API Key",
            "name": "EDGECENTER_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "EdgeCenter.ru",
        "title": "EdgeCenter.ru"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_efficientip",
        "hook": "dns_efficientip",
        "options": [
          {
            "desc": "HTTP Basic Authentication credentials. E.g. \"username:password\"",
            "name": "EfficientIP_Creds",
            "optional": false
          },
          {
            "desc": "EfficientIP SOLIDserver Management IP address or FQDN.",
            "name": "EfficientIP_Server",
            "optional": false
          },
          {
            "desc": "Name of the DNS smart or server hosting the zone. Optional.",
            "name": "EfficientIP_DNS_Name",
            "optional": true
          },
          {
            "desc": "Name of the DNS view hosting the zone. Optional.",
            "name": "EfficientIP_View",
            "optional": true
          }
        ],
        "options_alt": [
          {
            "desc": "Alternative API token key, prefered over basic authentication.",
            "name": "EfficientIP_Token_Key",
            "optional": false
          },
          {
            "desc": "Alternative API token secret, required when using a token key.",
            "name": "EfficientIP_Token_Secret",
            "optional": false
          },
          {
            "desc": "EfficientIP SOLIDserver Management IP address or FQDN.",
            "name": "EfficientIP_Server",
            "optional": false
          },
          {
            "desc": "Name of the DNS smart or server hosting the zone. Optional.",
            "name": "EfficientIP_DNS_Name",
            "optional": true
          },
          {
            "desc": "Name of the DNS view hosting the zone. Optional.",
            "name": "EfficientIP_View",
            "optional": true
          }
        ],
        "site": "https://efficientip.com/",
        "title": "efficientip.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_eurodns",
        "hook": "dns_eurodns",
        "options": [
          {
            "desc": "Application ID",
            "name": "EURODNS_APP_ID",
            "optional": false
          },
          {
            "desc": "API Key",
            "name": "EURODNS_API_KEY",
            "optional": false
          },
          {
            "desc": "TTL. Default: \"600\".",
            "name": "EURODNS_TTL",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "eurodns.com",
        "title": "EuroDNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_euserv",
        "hook": "dns_euserv",
        "options": [
          {
            "desc": "Username",
            "name": "EUSERV_Username",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "EUSERV_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "EUserv.com",
        "title": "EUserv.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_exoscale",
        "hook": "dns_exoscale",
        "options": [
          {
            "desc": "API Key",
            "name": "EXOSCALE_API_KEY",
            "optional": false
          },
          {
            "desc": "API Secret key",
            "name": "EXOSCALE_SECRET_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Exoscale.com",
        "title": "Exoscale.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_firestorm",
        "hook": "dns_firestorm",
        "options": [
          {
            "desc": "Customer ID",
            "name": "FST_Key",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "FST_Secret",
            "optional": false
          },
          {
            "desc": "API URL. Optional. Default \"https://api.firestorm.ch/acme-dns\".",
            "name": "FST_Url",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "firestorm.ch",
        "title": "Firestorm.ch"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_fornex",
        "hook": "dns_fornex",
        "options": [
          {
            "desc": "API Key",
            "name": "FORNEX_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Fornex.com",
        "title": "Fornex.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_freedns",
        "hook": "dns_freedns",
        "options": [
          {
            "desc": "Username",
            "name": "FREEDNS_User",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "FREEDNS_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "FreeDNS.afraid.org",
        "title": "FreeDNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_freemyip",
        "hook": "dns_freemyip",
        "options": [
          {
            "desc": "API Token",
            "name": "FREEMYIP_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "FreeMyIP.com",
        "title": "FreeMyIP.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_gandi_livedns",
        "hook": "dns_gandi_livedns",
        "options": [
          {
            "desc": "API Key",
            "name": "GANDI_LIVEDNS_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Gandi.net/domain/dns",
        "title": "Gandi.net LiveDNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_gcore",
        "hook": "dns_gcore",
        "options": [
          {
            "desc": "API Key",
            "name": "GCORE_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Gcore.com",
        "title": "Gcore.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_geoscaling",
        "hook": "dns_geoscaling",
        "options": [
          {
            "desc": "Username. This is usually NOT an email address",
            "name": "GEOSCALING_Username",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "GEOSCALING_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "GeoScaling.com",
        "title": "GeoScaling.com"
      },
      {
        "docs": "https://github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_glesys",
        "hook": "dns_glesys",
        "options": [
          {
            "desc": "Generated API key.",
            "name": "GLESYS_API_KEY",
            "optional": false
          },
          {
            "desc": "Project ID for the API key (e.g. cl12345).",
            "name": "GLESYS_PROJECT_ID",
            "optional": false
          },
          {
            "desc": "API endpoint. Default \"https://api.glesys.com/domain\".",
            "name": "GLESYS_API",
            "optional": false
          },
          {
            "desc": "TXT record TTL. Default 120.",
            "name": "GLESYS_TTL",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Glesys.se",
        "title": "Glesys"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_gname",
        "hook": "dns_gname",
        "options": [
          {
            "desc": "Your APPID",
            "name": "GNAME_APPID",
            "optional": false
          },
          {
            "desc": "Your APPKEY",
            "name": "GNAME_APPKEY",
            "optional": false
          },
          {
            "desc": "DNS resolution record TTL value, default 120.",
            "name": "GNAME_TTL",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "www.gname.com",
        "title": "GNAME"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_gd",
        "hook": "dns_gd",
        "options": [
          {
            "desc": "API Key",
            "name": "GD_Key",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "GD_Secret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "GoDaddy.com",
        "title": "GoDaddy.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_gcloud",
        "hook": "dns_gcloud",
        "options": [
          {
            "desc": "Active config name. E.g. \"default\"",
            "name": "CLOUDSDK_ACTIVE_CONFIG_NAME",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Cloud.Google.com/dns",
        "title": "Google Cloud DNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_googledomains",
        "hook": "dns_googledomains",
        "options": [
          {
            "desc": "API Access Token",
            "name": "GOOGLEDOMAINS_ACCESS_TOKEN",
            "optional": false
          },
          {
            "desc": "Zone",
            "name": "GOOGLEDOMAINS_ZONE",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Domains.Google.com",
        "title": "Google Domains"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_hetznercloud",
        "hook": "dns_hetznercloud",
        "options": [
          {
            "desc": "API token for the Hetzner Cloud DNS API",
            "name": "HETZNER_TOKEN",
            "optional": false
          },
          {
            "desc": "Custom TTL for new TXT rrsets (default 120)",
            "name": "HETZNER_TTL",
            "optional": true
          },
          {
            "desc": "Override API endpoint (default https://api.hetzner.cloud/v1)",
            "name": "HETZNER_API",
            "optional": true
          },
          {
            "desc": "Number of 1s polls to wait for async actions (default 120)",
            "name": "HETZNER_MAX_ATTEMPTS",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "Hetzner.com",
        "title": "Hetzner Cloud DNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_hexonet",
        "hook": "dns_hexonet",
        "options": [
          {
            "desc": "Login. E.g. \"username!roleId\"",
            "name": "Hexonet_Login",
            "optional": false
          },
          {
            "desc": "Role Password",
            "name": "Hexonet_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Hexonet.com",
        "title": "Hexonet.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_hostingde",
        "hook": "dns_hostingde",
        "options": [
          {
            "desc": "Endpoint. E.g. \"https://secure.hosting.de\"",
            "name": "HOSTINGDE_ENDPOINT",
            "optional": false
          },
          {
            "desc": "API Key",
            "name": "HOSTINGDE_APIKEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Hosting.de",
        "title": "Hosting.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_hostinger",
        "hook": "dns_hostinger",
        "options": [
          {
            "desc": "API Key",
            "name": "HOSTINGER_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Hostinger.com",
        "title": "Hostinger"
      },
      {
        "docs": "https://developer.hostup.se/",
        "hook": "dns_hostup",
        "options": [
          {
            "desc": "Required. HostUp API key with read:dns + write:dns + read:domains scopes.",
            "name": "HOSTUP_API_KEY",
            "optional": false
          },
          {
            "desc": "Optional. Override API base URL (default: https://cloud.hostup.se/api/v2).",
            "name": "HOSTUP_API_BASE",
            "optional": true
          },
          {
            "desc": "Optional. TTL for TXT records (default: 60 seconds).",
            "name": "HOSTUP_TTL",
            "optional": true
          },
          {
            "desc": "Optional. Force a specific v2 zone ID (zone_...) and skip auto-detection.",
            "name": "HOSTUP_ZONE_ID",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "hostup.se",
        "title": "HostUp DNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_huaweicloud",
        "hook": "dns_huaweicloud",
        "options": [
          {
            "desc": "Username",
            "name": "HUAWEICLOUD_Username",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "HUAWEICLOUD_Password",
            "optional": false
          },
          {
            "desc": "DomainName",
            "name": "HUAWEICLOUD_DomainName",
            "optional": false
          },
          {
            "desc": "Region. E.g. \"cn-north-4\". Optional, defaults to \"ap-southeast-1\".",
            "name": "HUAWEICLOUD_Region",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "HuaweiCloud.com",
        "title": "HuaweiCloud.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_he",
        "hook": "dns_he",
        "options": [
          {
            "desc": "Username",
            "name": "HE_Username",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "HE_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "dns.he.net",
        "title": "Hurricane Electric HE.net"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_he_ddns",
        "hook": "dns_he_ddns",
        "options": [
          {
            "desc": "The DDNS key",
            "name": "HE_DDNS_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "dns.he.net",
        "title": "Hurricane Electric HE.net DDNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_infoblox_uddi",
        "hook": "dns_infoblox_uddi",
        "options": [
          {
            "desc": "API Key for Infoblox UDDI",
            "name": "Infoblox_UDDI_Key",
            "optional": false
          },
          {
            "desc": "URL, e.g. \"csp.infoblox.com\" or \"csp.eu.infoblox.com\"",
            "name": "Infoblox_Portal",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Infoblox.com",
        "title": "Infoblox UDDI"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_infoblox",
        "hook": "dns_infoblox",
        "options": [
          {
            "desc": "Credentials. E.g. \"username:password\"",
            "name": "Infoblox_Creds",
            "optional": false
          },
          {
            "desc": "Server hostname. IP or FQDN of infoblox appliance",
            "name": "Infoblox_Server",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Infoblox.com",
        "title": "Infoblox.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_infomaniak",
        "hook": "dns_infomaniak",
        "options": [
          {
            "desc": "API Token",
            "name": "INFOMANIAK_API_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Infomaniak.com",
        "title": "Infomaniak.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_internetbs",
        "hook": "dns_internetbs",
        "options": [
          {
            "desc": "API Key",
            "name": "INTERNETBS_API_KEY",
            "optional": false
          },
          {
            "desc": "API Password",
            "name": "INTERNETBS_API_PASSWORD",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "InternetBS.net",
        "title": "InternetBS.net"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_autodns",
        "hook": "dns_autodns",
        "options": [
          {
            "desc": "Username",
            "name": "AUTODNS_USER",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "AUTODNS_PASSWORD",
            "optional": false
          },
          {
            "desc": "Context",
            "name": "AUTODNS_CONTEXT",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "InternetX.com/autodns/",
        "title": "InternetX autoDNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_inwx",
        "hook": "dns_inwx",
        "options": [
          {
            "desc": "Username",
            "name": "INWX_User",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "INWX_Password",
            "optional": false
          },
          {
            "desc": "2 Factor Authentication Shared Secret (optional requires oathtool)",
            "name": "INWX_Shared_Secret",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "INWX.de",
        "title": "INWX.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_ionos_cloud",
        "hook": "dns_ionos_cloud",
        "options": [
          {
            "desc": "API Token.",
            "name": "IONOS_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ionos.com",
        "title": "IONOS Cloud DNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_ionos",
        "hook": "dns_ionos",
        "options": [
          {
            "desc": "Prefix",
            "name": "IONOS_PREFIX",
            "optional": false
          },
          {
            "desc": "Secret",
            "name": "IONOS_SECRET",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "IONOS.de",
        "title": "IONOS.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_ipprojects",
        "hook": "dns_ipprojects",
        "options": [
          {
            "desc": "API Key",
            "name": "IPP_Apikey",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ip-projects.de/",
        "title": "IP-Projects DNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_ipv64",
        "hook": "dns_ipv64",
        "options": [
          {
            "desc": "API Token",
            "name": "IPv64_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "IPv64.net",
        "title": "IPv64.net"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_ispconfig",
        "hook": "dns_ispconfig",
        "options": [
          {
            "desc": "Remote User",
            "name": "ISPC_User",
            "optional": false
          },
          {
            "desc": "Remote Password",
            "name": "ISPC_Password",
            "optional": false
          },
          {
            "desc": "API URL. E.g. \"https://ispc.domain.tld:8080/remote/json.php\"",
            "name": "ISPC_Api",
            "optional": false
          },
          {
            "desc": "Insecure TLS. 0: check for cert validity, 1: always accept",
            "name": "ISPC_Api_Insecure",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ISPConfig.org",
        "title": "ISPConfig Server API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_jd",
        "hook": "dns_jd",
        "options": [
          {
            "desc": "Access key ID",
            "name": "JD_ACCESS_KEY_ID",
            "optional": false
          },
          {
            "desc": "Access key secret",
            "name": "JD_ACCESS_KEY_SECRET",
            "optional": false
          },
          {
            "desc": "Region. E.g. \"cn-north-1\"",
            "name": "JD_REGION",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "jdcloud.com",
        "title": "jdcloud.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_joker",
        "hook": "dns_joker",
        "options": [
          {
            "desc": "Username",
            "name": "JOKER_USERNAME",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "JOKER_PASSWORD",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Joker.com",
        "title": "Joker.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_kappernet",
        "hook": "dns_kappernet",
        "options": [
          {
            "desc": "API Key",
            "name": "KAPPERNETDNS_Key",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "KAPPERNETDNS_Secret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "kapper.net",
        "title": "kapper.net"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_kinghost",
        "hook": "dns_kinghost",
        "options": [
          {
            "desc": "Username",
            "name": "KINGHOST_Username",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "KINGHOST_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "King.host",
        "title": "King.host"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_knot",
        "hook": "dns_knot",
        "options": [
          {
            "desc": "Server hostname. Default: \"localhost\".",
            "name": "KNOT_SERVER",
            "optional": false
          },
          {
            "desc": "TSIG key data, not a file path. knsupdate \"key\" statement format: \"[alg:]name secret\". E.g. \"hmac-sha256:acme_key BASE64SECRET=\"",
            "name": "KNOT_KEY",
            "optional": false
          },
          {
            "desc": "Zone name. Optional, set it when the challenge record lives in a delegated subdomain zone. Default: the parent domain of the challenge record.",
            "name": "KNOT_ZONE",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "www.knot-dns.cz/docs/2.5/html/man_knsupdate.html",
        "title": "Knot Server knsupdate"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_laodc",
        "hook": "dns_laodc",
        "options": [
          {
            "desc": "API Key",
            "name": "LaoDC_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "laodc.com",
        "title": "LaoDC DNS API Server"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_leaseweb",
        "hook": "dns_leaseweb",
        "options": [
          {
            "desc": "API Key",
            "name": "LSW_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Leaseweb.com",
        "title": "Leaseweb.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_level27",
        "hook": "dns_level27",
        "options": [
          {
            "desc": "API key. Get one from the Level27 control panel (https://app.level27.eu/account/profile/security).",
            "name": "LEVEL27_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [
          {
            "desc": "API base URL. Optional. Default \"https://api.level27.eu/v1\".",
            "name": "LEVEL27_API",
            "optional": true
          }
        ],
        "site": "Level27.be",
        "title": "Level27"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/How-to-use-lexicon-DNS-API",
        "hook": "dns_lexicon",
        "options": [
          {
            "desc": "Provider",
            "name": "PROVIDER",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "github.com/AnalogJ/lexicon",
        "title": "Lexicon DNS client"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_limacity",
        "hook": "dns_limacity",
        "options": [
          {
            "desc": "API Key. Note: The API Key must have following roles: dns.admin, domains.reader",
            "name": "LIMACITY_APIKEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "www.lima-city.de",
        "title": "lima-city.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_linode_v4",
        "hook": "dns_linode_v4",
        "options": [
          {
            "desc": "API Key",
            "name": "LINODE_V4_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Linode.com",
        "title": "Linode.com"
      },
      {
        "docs": "",
        "hook": "dns_linode",
        "options": [
          {
            "desc": "API Key",
            "name": "LINODE_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Linode.com",
        "title": "Linode.com (Old)"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_loopia",
        "hook": "dns_loopia",
        "options": [
          {
            "desc": "API URL. E.g. \"https://api.loopia.<TLD>/RPCSERV\" where the <TLD> is one of: com, no, rs, se. Default: \"se\".",
            "name": "LOOPIA_Api",
            "optional": false
          },
          {
            "desc": "Username",
            "name": "LOOPIA_User",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "LOOPIA_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Loopia.se",
        "title": "Loopia.se"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_lua",
        "hook": "dns_lua",
        "options": [
          {
            "desc": "API key",
            "name": "LUA_Key",
            "optional": false
          },
          {
            "desc": "Email",
            "name": "LUA_Email",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "LuaDNS.com",
        "title": "LuaDNS.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_miab",
        "hook": "dns_miab",
        "options": [
          {
            "desc": "Admin username",
            "name": "MIAB_Username",
            "optional": false
          },
          {
            "desc": "Admin password",
            "name": "MIAB_Password",
            "optional": false
          },
          {
            "desc": "Server hostname. FQDN of your_MIAB Server",
            "name": "MIAB_Server",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "MailInaBox.email",
        "title": "Mail-in-a-Box"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_maradns",
        "hook": "dns_maradns",
        "options": [
          {
            "desc": "Zone file path. E.g. \"/etc/maradns/db.domain.com\"",
            "name": "MARA_ZONE_FILE",
            "optional": false
          },
          {
            "desc": "Duende PID Path. E.g. \"/run/maradns/etc_maradns_mararc.pid\"",
            "name": "MARA_DUENDE_PID_PATH",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "MaraDNS.samiam.org",
        "title": "MaraDNS Server"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_mgwm",
        "hook": "dns_mgwm",
        "options": [
          {
            "desc": "Your customer number",
            "name": "MGWM_CUSTOMER",
            "optional": false
          },
          {
            "desc": "Your API Hash",
            "name": "MGWM_API_HASH",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "mgw-media.de",
        "title": "mgw-media.de"
      },
      {
        "docs": "https://github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_mijnhost",
        "hook": "dns_mijnhost",
        "options": [
          {
            "desc": "API Key",
            "name": "MIJNHOST_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "mijn.host",
        "title": "mijn.host"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_misaka",
        "hook": "dns_misaka",
        "options": [
          {
            "desc": "API Key",
            "name": "Misaka_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Misaka.io",
        "title": "Misaka.io"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_muumuu",
        "hook": "dns_muumuu",
        "options": [
          {
            "desc": "Personal Access Token (scopes: domains:read, dns:read, dns:write)",
            "name": "MUUMUU_PAT",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "muumuu-domain.com",
        "title": "muumuu-domain.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_mydevil",
        "hook": "dns_mydevil",
        "options": [],
        "options_alt": [],
        "site": "MyDevil.net",
        "title": "MyDevil.net"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_mydnsjp",
        "hook": "dns_mydnsjp",
        "options": [
          {
            "desc": "Master ID",
            "name": "MYDNSJP_MasterID",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "MYDNSJP_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "MyDNS.JP",
        "title": "MyDNS.JP"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_mythic_beasts",
        "hook": "dns_mythic_beasts",
        "options": [
          {
            "desc": "API Key",
            "name": "MB_AK",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "MB_AS",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Mythic-Beasts.com",
        "title": "Mythic-Beasts.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_namecom",
        "hook": "dns_namecom",
        "options": [
          {
            "desc": "Username",
            "name": "Namecom_Username",
            "optional": false
          },
          {
            "desc": "API Token",
            "name": "Namecom_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Name.com",
        "title": "Name.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_namecheap",
        "hook": "dns_namecheap",
        "options": [
          {
            "desc": "API Key",
            "name": "NAMECHEAP_API_KEY",
            "optional": false
          },
          {
            "desc": "Username",
            "name": "NAMECHEAP_USERNAME",
            "optional": false
          },
          {
            "desc": "Source IP",
            "name": "NAMECHEAP_SOURCEIP",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "NameCheap.com",
        "title": "NameCheap.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_nm",
        "hook": "dns_nm",
        "options": [
          {
            "desc": "API Username",
            "name": "NM_user",
            "optional": false
          },
          {
            "desc": "API Password as SHA256 hash",
            "name": "NM_sha256",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "NameMaster.de",
        "title": "NameMaster.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_namesilo",
        "hook": "dns_namesilo",
        "options": [
          {
            "desc": "API Key",
            "name": "Namesilo_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "NameSilo.com",
        "title": "NameSilo.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_nanelo",
        "hook": "dns_nanelo",
        "options": [
          {
            "desc": "API Token",
            "name": "NANELO_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Nanelo.com",
        "title": "Nanelo.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_nederhost",
        "hook": "dns_nederhost",
        "options": [
          {
            "desc": "API Key",
            "name": "NederHost_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "NederHost.nl",
        "title": "NederHost.nl"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_neodigit",
        "hook": "dns_neodigit",
        "options": [
          {
            "desc": "API Token",
            "name": "NEODIGIT_API_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Neodigit.net",
        "title": "Neodigit.net"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_netcup",
        "hook": "dns_netcup",
        "options": [
          {
            "desc": "API Key",
            "name": "NC_Apikey",
            "optional": false
          },
          {
            "desc": "API Password",
            "name": "NC_Apipw",
            "optional": false
          },
          {
            "desc": "Customer Number",
            "name": "NC_CID",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "netcup.eu/",
        "title": "netcup.eu"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_netlify",
        "hook": "dns_netlify",
        "options": [
          {
            "desc": "API Token",
            "name": "NETLIFY_ACCESS_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Netlify.com",
        "title": "Netlify.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_nw",
        "hook": "dns_nw",
        "options": [
          {
            "desc": "API Token",
            "name": "NW_API_TOKEN",
            "optional": false
          },
          {
            "desc": "API Endpoint. Default: \"https://portal.nexcess.net\".",
            "name": "NW_API_ENDPOINT",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Nexcess.net",
        "title": "Nexcess.net (NocWorx)"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_nic",
        "hook": "dns_nic",
        "options": [
          {
            "desc": "Client ID",
            "name": "NIC_ClientID",
            "optional": false
          },
          {
            "desc": "Client Secret",
            "name": "NIC_ClientSecret",
            "optional": false
          },
          {
            "desc": "Username",
            "name": "NIC_Username",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "NIC_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "nic.ru",
        "title": "nic.ru"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_njalla",
        "hook": "dns_njalla",
        "options": [
          {
            "desc": "API Token",
            "name": "NJALLA_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Njal.la",
        "title": "Njalla"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#nsd",
        "hook": "dns_nsd",
        "options": [
          {
            "desc": "Zone File path. E.g. \"/etc/nsd/zones/example.com.zone\"",
            "name": "Nsd_ZoneFile",
            "optional": false
          },
          {
            "desc": "Command. E.g. \"sudo nsd-control reload\"",
            "name": "Nsd_Command",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "github.com/NLnetLabs/nsd",
        "title": "NLnetLabs NSD Server"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_nsone",
        "hook": "dns_nsone",
        "options": [
          {
            "desc": "API Key",
            "name": "NS1_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ns1.com",
        "title": "ns1.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_nsupdate",
        "hook": "dns_nsupdate",
        "options": [
          {
            "desc": "Server hostname. Default: \"localhost\".",
            "name": "NSUPDATE_SERVER",
            "optional": false
          },
          {
            "desc": "Server port. Default: \"53\".",
            "name": "NSUPDATE_SERVER_PORT",
            "optional": false
          },
          {
            "desc": "File path to TSIG key. Default: \"\". Optional.",
            "name": "NSUPDATE_KEY",
            "optional": true
          },
          {
            "desc": "Domain zone to update. Optional.",
            "name": "NSUPDATE_ZONE",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "bind9.readthedocs.io/en/v9.18.19/manpages.html#nsupdate-dynamic-dns-update-utility",
        "title": "nsupdate RFC 2136 DynDNS client"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_omglol",
        "hook": "dns_omglol",
        "options": [
          {
            "desc": "- API Key. This is accessible from the bottom of the account page at https://home.omg.lol/account",
            "name": "OMG_ApiKey",
            "optional": false
          },
          {
            "desc": "- Address. This is your omg.lol address, without the preceding @ - you can see your list on your dashboard at https://home.omg.lol/dashboard",
            "name": "OMG_Address",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "omg.lol",
        "title": "omg.lol"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_one",
        "hook": "dns_one",
        "options": [
          {
            "desc": "Username",
            "name": "ONECOM_User",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "ONECOM_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "one.com",
        "title": "one.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_online",
        "hook": "dns_online",
        "options": [
          {
            "desc": "API Key",
            "name": "ONLINE_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "online.net",
        "title": "online.net"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_openprovider_rest",
        "hook": "dns_openprovider_rest",
        "options": [
          {
            "desc": "Openprovider Account Username",
            "name": "OPENPROVIDER_REST_USERNAME",
            "optional": false
          },
          {
            "desc": "Openprovider Account Password",
            "name": "OPENPROVIDER_REST_PASSWORD",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "OpenProvider.eu",
        "title": "OpenProvider (REST)"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_openprovider",
        "hook": "dns_openprovider",
        "options": [
          {
            "desc": "Username",
            "name": "OPENPROVIDER_USER",
            "optional": false
          },
          {
            "desc": "Password hash",
            "name": "OPENPROVIDER_PASSWORDHASH",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "OpenProvider.eu",
        "title": "OpenProvider.eu"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_openstack",
        "hook": "dns_openstack",
        "options": [
          {
            "desc": "Auth URL. E.g. \"https://keystone.example.com:5000/\"",
            "name": "OS_AUTH_URL",
            "optional": false
          },
          {
            "desc": "Username",
            "name": "OS_USERNAME",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "OS_PASSWORD",
            "optional": false
          },
          {
            "desc": "Project name",
            "name": "OS_PROJECT_NAME",
            "optional": false
          },
          {
            "desc": "Project domain name. E.g. \"Default\"",
            "name": "OS_PROJECT_DOMAIN_NAME",
            "optional": false
          },
          {
            "desc": "User domain name. E.g. \"Default\"",
            "name": "OS_USER_DOMAIN_NAME",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "docs.openstack.org/api-ref/dns/",
        "title": "OpenStack Designate API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_opnsense",
        "hook": "dns_opnsense",
        "options": [
          {
            "desc": "Server Hostname. E.g. \"opnsense.example.com\"",
            "name": "OPNs_Host",
            "optional": false
          },
          {
            "desc": "Port. Default: \"443\".",
            "name": "OPNs_Port",
            "optional": false
          },
          {
            "desc": "API Key",
            "name": "OPNs_Key",
            "optional": false
          },
          {
            "desc": "API Token",
            "name": "OPNs_Token",
            "optional": false
          },
          {
            "desc": "Insecure TLS. 0: check for cert validity, 1: always accept",
            "name": "OPNs_Api_Insecure",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "docs.opnsense.org/development/api.html",
        "title": "OPNsense Server"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_opusdns",
        "hook": "dns_opusdns",
        "options": [
          {
            "desc": "API Key. Can be created at https://dashboard.opusdns.com/settings/api-keys",
            "name": "OPUSDNS_API_Key",
            "optional": false
          },
          {
            "desc": "API Endpoint URL. Default \"https://api.opusdns.com\". Optional.",
            "name": "OPUSDNS_API_Endpoint",
            "optional": true
          },
          {
            "desc": "TTL for DNS challenge records in seconds. Default \"60\". Optional.",
            "name": "OPUSDNS_TTL",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "OpusDNS.com",
        "title": "OpusDNS.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/How-to-use-Oracle-Cloud-Infrastructure-DNS",
        "hook": "dns_oci",
        "options": [
          {
            "desc": "OCID of tenancy that contains the target DNS zone. Optional.",
            "name": "OCI_CLI_TENANCY",
            "optional": true
          },
          {
            "desc": "OCID of user with permission to add/remove records from zones. Optional.",
            "name": "OCI_CLI_USER",
            "optional": true
          },
          {
            "desc": "Should point to the tenancy home region. Optional.",
            "name": "OCI_CLI_REGION",
            "optional": true
          },
          {
            "desc": "Path to private API signing key file in PEM format. Optional.",
            "name": "OCI_CLI_KEY_FILE",
            "optional": true
          },
          {
            "desc": "The private API signing key in PEM format. Optional.",
            "name": "OCI_CLI_KEY",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "Cloud.Oracle.com",
        "title": "Oracle Cloud Infrastructure (OCI)"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/How-to-use-OVH-domain-api",
        "hook": "dns_ovh",
        "options": [
          {
            "desc": "Endpoint. \"ovh-eu\", \"ovh-us\", \"ovh-ca\", \"kimsufi-eu\", \"kimsufi-ca\", \"soyoustart-eu\", \"soyoustart-ca\" or raw URL. Default: \"ovh-eu\".",
            "name": "OVH_END_POINT",
            "optional": false
          },
          {
            "desc": "Application Key",
            "name": "OVH_AK",
            "optional": false
          },
          {
            "desc": "Application Secret",
            "name": "OVH_AS",
            "optional": false
          },
          {
            "desc": "Consumer Key",
            "name": "OVH_CK",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "OVH.com",
        "title": "OVH.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_pleskxml",
        "hook": "dns_pleskxml",
        "options": [
          {
            "desc": "Plesk server API URL. E.g. \"https://your-plesk-server.net:8443/enterprise/control/agent.php\"",
            "name": "pleskxml_uri",
            "optional": false
          },
          {
            "desc": "Username",
            "name": "pleskxml_user",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "pleskxml_pass",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Plesk.com",
        "title": "Plesk Server API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_pointhq",
        "hook": "dns_pointhq",
        "options": [
          {
            "desc": "API Key",
            "name": "PointHQ_Key",
            "optional": false
          },
          {
            "desc": "Email",
            "name": "PointHQ_Email",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "pointhq.com",
        "title": "pointhq.com PointDNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_porkbun",
        "hook": "dns_porkbun",
        "options": [
          {
            "desc": "API Key",
            "name": "PORKBUN_API_KEY",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "PORKBUN_SECRET_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Porkbun.com",
        "title": "Porkbun.com"
      },
      {
        "docs": "https://github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_poweradmin",
        "hook": "dns_poweradmin",
        "options": [
          {
            "desc": "API URL (with scheme). E.g. \"https://poweradmin.example.com\" or \"http://192.168.0.10:8080\"",
            "name": "POWERADMIN_URL",
            "optional": false
          },
          {
            "desc": "API Token \"pwa_xxxx\"",
            "name": "POWERADMIN_API_KEY",
            "optional": false
          },
          {
            "desc": "Optionally override Poweradmin API version.",
            "name": "POWERADMIN_API_VERSION",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "https://www.poweradmin.org/",
        "title": "Poweradmin API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_pdns",
        "hook": "dns_pdns",
        "options": [
          {
            "desc": "API URL. E.g. \"http://ns.example.com:8081\"",
            "name": "PDNS_Url",
            "optional": false
          },
          {
            "desc": "Server ID. E.g. \"localhost\"",
            "name": "PDNS_ServerId",
            "optional": false
          },
          {
            "desc": "API Token",
            "name": "PDNS_Token",
            "optional": false
          },
          {
            "desc": "Domain TTL. Default: \"60\".",
            "name": "PDNS_Ttl",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "PowerDNS.com",
        "title": "PowerDNS Server API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_qc",
        "hook": "dns_qc",
        "options": [
          {
            "desc": "QC API Key",
            "name": "QC_API_KEY",
            "optional": false
          },
          {
            "desc": "Your account email",
            "name": "QC_API_EMAIL",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "quic.cloud",
        "title": "QUIC.cloud"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_rackcorp",
        "hook": "dns_rackcorp",
        "options": [
          {
            "desc": "API UUID. See Portal: ADMINISTRATION -> API",
            "name": "RACKCORP_APIUUID",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "RACKCORP_APISECRET",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "RackCorp.com",
        "title": "RackCorp.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_rackspace",
        "hook": "dns_rackspace",
        "options": [
          {
            "desc": "API Key",
            "name": "RACKSPACE_Apikey",
            "optional": false
          },
          {
            "desc": "Username",
            "name": "RACKSPACE_Username",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "RackSpace.com",
        "title": "RackSpace.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_rage4",
        "hook": "dns_rage4",
        "options": [
          {
            "desc": "API Key",
            "name": "RAGE4_TOKEN",
            "optional": false
          },
          {
            "desc": "Username",
            "name": "RAGE4_USERNAME",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "rage4.com",
        "title": "rage4.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_rcode0",
        "hook": "dns_rcode0",
        "options": [
          {
            "desc": "API URL. E.g. \"https://my.rcodezero.at\"",
            "name": "RCODE0_URL",
            "optional": false
          },
          {
            "desc": "API Token",
            "name": "RCODE0_API_TOKEN",
            "optional": false
          },
          {
            "desc": "TTL. Default: \"60\".",
            "name": "RCODE0_TTL",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "rcodezero.at",
        "title": "Rcode0 rcodezero.at"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_regru",
        "hook": "dns_regru",
        "options": [
          {
            "desc": "Username",
            "name": "REGRU_API_Username",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "REGRU_API_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "reg.ru",
        "title": "reg.ru"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_scaleway",
        "hook": "dns_scaleway",
        "options": [
          {
            "desc": "API Token",
            "name": "SCALEWAY_API_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ScaleWay.com",
        "title": "ScaleWay.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_schlundtech",
        "hook": "dns_schlundtech",
        "options": [
          {
            "desc": "Username",
            "name": "SCHLUNDTECH_USER",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "SCHLUNDTECH_PASSWORD",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "SchlundTech.de",
        "title": "SchlundTech.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_selectel",
        "hook": "dns_selectel",
        "options": [
          {
            "desc": "API version. Use \"v1\".",
            "name": "SL_Ver",
            "optional": false
          },
          {
            "desc": "API Key",
            "name": "SL_Key",
            "optional": false
          }
        ],
        "options_alt": [
          {
            "desc": "API version. Use \"v2\".",
            "name": "SL_Ver",
            "optional": false
          },
          {
            "desc": "Account ID",
            "name": "SL_Login_ID",
            "optional": false
          },
          {
            "desc": "Project name",
            "name": "SL_Project_Name",
            "optional": false
          },
          {
            "desc": "Service user name",
            "name": "SL_Login_Name",
            "optional": false
          },
          {
            "desc": "Service user password",
            "name": "SL_Pswd",
            "optional": false
          },
          {
            "desc": "Token lifetime. In minutes (0-1440). Default \"1400\"",
            "name": "SL_Expire",
            "optional": false
          }
        ],
        "site": "Selectel.com",
        "title": "Selectel.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_selfhost",
        "hook": "dns_selfhost",
        "options": [
          {
            "desc": "Username",
            "name": "SELFHOSTDNS_USERNAME",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "SELFHOSTDNS_PASSWORD",
            "optional": false
          },
          {
            "desc": "Subdomain name",
            "name": "SELFHOSTDNS_MAP",
            "optional": false
          },
          {
            "desc": "API url. Optional. Default \"https://account.selfhost.de/cgi-bin/api.pl\"",
            "name": "SELFHOSTDNS_UPDATE_URL",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "SelfHost.de",
        "title": "SelfHost.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_servercow",
        "hook": "dns_servercow",
        "options": [
          {
            "desc": "Username",
            "name": "SERVERCOW_API_Username",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "SERVERCOW_API_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ServerCow.de",
        "title": "ServerCow.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_simply",
        "hook": "dns_simply",
        "options": [
          {
            "desc": "Account name",
            "name": "SIMPLY_AccountName",
            "optional": false
          },
          {
            "desc": "API Key",
            "name": "SIMPLY_ApiKey",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Simply.com",
        "title": "Simply.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_sitehost",
        "hook": "dns_sitehost",
        "options": [
          {
            "desc": "API Key",
            "name": "SITEHOST_API_KEY",
            "optional": false
          },
          {
            "desc": "Client ID. The numeric client ID for your SiteHost account.",
            "name": "SITEHOST_CLIENT_ID",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "sitehost.nz",
        "title": "SiteHost"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_sotoon",
        "hook": "dns_sotoon",
        "options": [
          {
            "desc": "API Token",
            "name": "Sotoon_Token",
            "optional": false
          },
          {
            "desc": "Workspace UUID",
            "name": "Sotoon_WorkspaceUUID",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Sotoon.ir",
        "title": "Sotoon.ir"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_spaceship",
        "hook": "dns_spaceship",
        "options": [
          {
            "desc": "API Key",
            "name": "SPACESHIP_API_KEY",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "SPACESHIP_API_SECRET",
            "optional": false
          },
          {
            "desc": "Root domain. Manually specify the root domain if auto-detection fails. Optional.",
            "name": "SPACESHIP_ROOT_DOMAIN",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "Spaceship.com",
        "title": "Spaceship.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_subreg",
        "hook": "dns_subreg",
        "options": [
          {
            "desc": "API username",
            "name": "SUBREG_API_USERNAME",
            "optional": false
          },
          {
            "desc": "API password",
            "name": "SUBREG_API_PASSWORD",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "subreg.cz",
        "title": "Subreg.cz"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_technitium",
        "hook": "dns_technitium",
        "options": [
          {
            "desc": "Server Address",
            "name": "Technitium_Server",
            "optional": false
          },
          {
            "desc": "API Token",
            "name": "Technitium_Token",
            "optional": false
          },
          {
            "desc": "Number of seconds before DNS server auto-deletes the acme record",
            "name": "Technitium_Expiry_Ttl",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Technitium.com/dns/",
        "title": "Technitium DNS Server"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#tele3",
        "hook": "dns_tele3",
        "options": [
          {
            "desc": "API Key",
            "name": "TELE3_Key",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "TELE3_Secret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "tele3.cz",
        "title": "tele3.cz"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_tencent",
        "hook": "dns_tencent",
        "options": [
          {
            "desc": "Secret ID",
            "name": "Tencent_SecretId",
            "optional": false
          },
          {
            "desc": "Secret Key",
            "name": "Tencent_SecretKey",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "cloud.Tencent.com",
        "title": "Tencent.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_timeweb",
        "hook": "dns_timeweb",
        "options": [
          {
            "desc": "API JWT token. Get it from the control panel at https://timeweb.cloud/my/api-keys",
            "name": "TW_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Timeweb.Cloud",
        "title": "Timeweb.Cloud"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_transip",
        "hook": "dns_transip",
        "options": [
          {
            "desc": "Username",
            "name": "TRANSIP_Username",
            "optional": false
          },
          {
            "desc": "Private key file path",
            "name": "TRANSIP_Key_File",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "TransIP.nl",
        "title": "TransIP.nl"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_ultra",
        "hook": "dns_ultra",
        "options": [
          {
            "desc": "Username",
            "name": "ULTRA_USR",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "ULTRA_PWD",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "UltraDNS.com",
        "title": "UltraDNS.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_udr",
        "hook": "dns_udr",
        "options": [
          {
            "desc": "Username",
            "name": "UDR_USER",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "UDR_PASS",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ud-reselling.com",
        "title": "united-domains Reselling"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_unoeuro",
        "hook": "dns_unoeuro",
        "options": [
          {
            "desc": "API Key",
            "name": "UNO_Key",
            "optional": false
          },
          {
            "desc": "Username",
            "name": "UNO_User",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "unoeuro.com",
        "title": "unoeuro.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_variomedia",
        "hook": "dns_variomedia",
        "options": [
          {
            "desc": "API Token",
            "name": "VARIOMEDIA_API_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "variomedia.de",
        "title": "variomedia.de"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_veesp",
        "hook": "dns_veesp",
        "options": [
          {
            "desc": "Username",
            "name": "VEESP_User",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "VEESP_Password",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "veesp.com",
        "title": "veesp.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_vercel",
        "hook": "dns_vercel",
        "options": [
          {
            "desc": "API Token",
            "name": "VERCEL_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Vercel.com",
        "title": "Vercel.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_aurora",
        "hook": "dns_aurora",
        "options": [
          {
            "desc": "API Key",
            "name": "AURORA_Key",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "AURORA_Secret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "versio.nl",
        "title": "versio.nl AuroraDNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_virakcloud",
        "hook": "dns_virakcloud",
        "options": [
          {
            "desc": "VirakCloud API Bearer Token",
            "name": "VIRAKCLOUD_API_TOKEN",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "VirakCloud.com",
        "title": "VirakCloud DNS API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_volcengine",
        "hook": "dns_volcengine",
        "options": [
          {
            "desc": "API Key ID",
            "name": "Volcengine_ACCESS_KEY_ID",
            "optional": false
          },
          {
            "desc": "API Secret",
            "name": "Volcengine_SECRET_ACCESS_KEY",
            "optional": false
          },
          {
            "desc": "Session Token. Optional, only needed when using temporary STS credentials.",
            "name": "Volcengine_SESSION_TOKEN",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "https://www.volcengine.com/docs/6758/155086",
        "title": "Volcano Engine DNS API"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_vscale",
        "hook": "dns_vscale",
        "options": [
          {
            "desc": "API Key",
            "name": "VSCALE_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "vscale.io",
        "title": "vscale.io"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_clouddns",
        "hook": "dns_clouddns",
        "options": [
          {
            "desc": "Email",
            "name": "CLOUDDNS_EMAIL",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "CLOUDDNS_PASSWORD",
            "optional": false
          },
          {
            "desc": "Client ID",
            "name": "CLOUDDNS_CLIENT_ID",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "github.com/vshosting/clouddns",
        "title": "vshosting.cz CloudDNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_vultr",
        "hook": "dns_vultr",
        "options": [
          {
            "desc": "API Key",
            "name": "VULTR_API_KEY",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "vultr.com",
        "title": "vultr.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_websupport",
        "hook": "dns_websupport",
        "options": [
          {
            "desc": "API Key. Called \"Identifier\" in the WS Admin",
            "name": "WS_ApiKey",
            "optional": false
          },
          {
            "desc": "API Secret. Called \"Secret key\" in the WS Admin",
            "name": "WS_ApiSecret",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Websupport.sk",
        "title": "Websupport.sk"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_wedos",
        "hook": "dns_wedos",
        "options": [
          {
            "desc": "WAPI login (account email)",
            "name": "WEDOS_Username",
            "optional": false
          },
          {
            "desc": "WAPI password",
            "name": "WEDOS_Wapipass",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "wedos.com",
        "title": "WEDOS.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_west_cn",
        "hook": "dns_west_cn",
        "options": [
          {
            "desc": "API username",
            "name": "WEST_Username",
            "optional": false
          },
          {
            "desc": "API Key. Set at https://www.west.cn/manager/API/APIconfig.asp",
            "name": "WEST_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "West.cn",
        "title": "West.cn"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_world4you",
        "hook": "dns_world4you",
        "options": [
          {
            "desc": "Username",
            "name": "WORLD4YOU_USERNAME",
            "optional": false
          },
          {
            "desc": "Password",
            "name": "WORLD4YOU_PASSWORD",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "World4You.com",
        "title": "World4You.com"
      },
      {
        "docs": "https://github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_yandex360",
        "hook": "dns_yandex360",
        "options": [
          {
            "desc": "OAuth 2.0 ClientID",
            "name": "YANDEX360_CLIENT_ID",
            "optional": false
          },
          {
            "desc": "OAuth 2.0 Client secret",
            "name": "YANDEX360_CLIENT_SECRET",
            "optional": false
          }
        ],
        "options_alt": [
          {
            "desc": "Organization ID. Optional.",
            "name": "YANDEX360_ORG_ID",
            "optional": true
          },
          {
            "desc": "OAuth 2.0 Access token. Optional.",
            "name": "YANDEX360_ACCESS_TOKEN",
            "optional": true
          }
        ],
        "site": "https://360.yandex.com/",
        "title": "Yandex 360 for Business DNS API."
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_yc",
        "hook": "dns_yc",
        "options": [
          {
            "desc": "DNS Zone ID",
            "name": "YC_Zone_ID",
            "optional": false
          },
          {
            "desc": "YC Folder ID",
            "name": "YC_Folder_ID",
            "optional": false
          },
          {
            "desc": "Service Account ID",
            "name": "YC_SA_ID",
            "optional": false
          },
          {
            "desc": "Service Account IAM Key ID",
            "name": "YC_SA_Key_ID",
            "optional": false
          },
          {
            "desc": "Private key file path. Optional.",
            "name": "YC_SA_Key_File_Path",
            "optional": true
          },
          {
            "desc": "Base64 content of private key file. Use instead of Path to private key file. Optional.",
            "name": "YC_SA_Key_File_PEM_b64",
            "optional": true
          }
        ],
        "options_alt": [],
        "site": "Cloud.Yandex.com",
        "title": "Yandex Cloud DNS"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_zilore",
        "hook": "dns_zilore",
        "options": [
          {
            "desc": "API Key",
            "name": "Zilore_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Zilore.com",
        "title": "Zilore.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_zone",
        "hook": "dns_zone",
        "options": [
          {
            "desc": "Username",
            "name": "ZONE_Username",
            "optional": false
          },
          {
            "desc": "API Key",
            "name": "ZONE_Key",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "Zone.eu",
        "title": "Zone.eu"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_zoneedit",
        "hook": "dns_zoneedit",
        "options": [
          {
            "desc": "ID",
            "name": "ZONEEDIT_ID",
            "optional": false
          },
          {
            "desc": "API Token",
            "name": "ZONEEDIT_Token",
            "optional": false
          }
        ],
        "options_alt": [],
        "site": "ZoneEdit.com",
        "title": "ZoneEdit.com"
      },
      {
        "docs": "github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_zonomi",
        "hook": "dns_zonomi",
        "options": [
          {
            "desc": "API Key",
            "name": "ZM_Key",
            "optional": false
          }
        ],
        "options_alt": [
          {
            "desc": "API endpoint. Default: \"https://zonomi.com/app/dns/dyndns.jsp\". For RimuHosting use \"https://rimuhosting.com/dns/dyndns.jsp\".",
            "name": "ZM_Api",
            "optional": false
          }
        ],
        "site": "zonomi.com",
        "title": "zonomi.com"
      }
    ],
    "note": "",
    "ok": true
  },
  "acme/health": {
    "hint": "",
    "home": "/var/lib/acme.sh",
    "ok": true,
    "path": "/var/lib/acme.sh/acme.sh",
    "problem": "",
    "version": "v3.1.4"
  },
  "cluster": {
    "age_seconds": 0,
    "live": true,
    "nodes": [
      {
        "certs_bad": 0,
        "certs_total": 0,
        "dirty": true,
        "error": "",
        "haproxy": "activating",
        "hostname": "293a0e497606",
        "id": "self",
        "keepalived": "disabled",
        "ms": 0,
        "name": "293a0e497606",
        "reachable": true,
        "role": "standalone",
        "self": true,
        "update_available": false,
        "url": "",
        "version": "1.51.0",
        "vip_held": [],
        "vips": []
      }
    ],
    "ok": true,
    "summary": {
      "active": 0,
      "reachable": 1,
      "total": 1,
      "warnings": [
        "Unapplied changes on: 293a0e497606."
      ]
    },
    "taken": "2026-08-11T02:23:25+00:00"
  },
  "cluster/settings": {
    "advert_int": 1,
    "auth_pass": "",
    "custom": "",
    "nopreempt": true,
    "state": "BACKUP",
    "track_haproxy": true,
    "vips": "",
    "vrid": 51
  },
  "cluster/unicast": {
    "addresses": [],
    "nodes": [
      {
        "address": "172.17.0.3",
        "how": "this node's eth0",
        "name": "293a0e497606",
        "self": true,
        "warning": ""
      }
    ],
    "ok": true
  },
  "keepalived/status": {
    "error": "the node hit an unexpected error",
    "ok": false
  },
  "local": {
    "admin": {
      "hash": "b37b3552650bfdca81fbed31aaed8f6c6f1a279de0afd5722ebba21d89f8fa8c",
      "iterations": 240000,
      "salt": "3a2b1645f8f1ea8fa6a0a2a468ffa102",
      "updated": "2026-08-11T02:23:24+00:00",
      "username": "a"
    },
    "api_key": "",
    "keepalived": {
      "advert_int": 1,
      "auth_pass": "",
      "custom": "",
      "enabled": false,
      "interface": "eth0",
      "nopreempt": true,
      "priority": 100,
      "state": "BACKUP",
      "track_haproxy": true,
      "unicast_peer": "",
      "unicast_src": "",
      "vips": "",
      "vrid": 51
    },
    "node_url": "",
    "session_hours": 12,
    "session_secret": "870b2c7a36424f6f7d13954d5e83ed780ace65ba6487622b86ab24cc6e9e648c",
    "sync": {
      "auto_sync": false,
      "peer_api_key": "",
      "peer_url": "",
      "peers": [],
      "verify_tls": false
    },
    "watchdog": {
      "enabled": true,
      "haproxy": true,
      "interval": 20,
      "keepalived": true,
      "max_restarts": 3,
      "window": 900
    },
    "web_ui": {
      "certificate": "auto",
      "enabled": false,
      "rule_id": "",
      "url": ""
    }
  },
  "logs": {
    "entries": [
      {
        "level": "INFO",
        "source": "manager",
        "text": "haproxy-manager 1.51.0 listening on 0.0.0.0:8080 (waitress)",
        "ts": 1786415003.0
      },
      {
        "level": "INFO",
        "source": "manager",
        "text": "Serving on http://0.0.0.0:8080",
        "ts": 1786415003.0
      },
      {
        "level": "INFO",
        "source": "manager",
        "text": "anonymous POST /api/setup -> 200 (192.168.65.1)",
        "ts": 1786415004.0
      },
      {
        "level": "INFO",
        "source": "manager",
        "text": "signed in: a from 192.168.65.1",
        "ts": 1786415004.0
      }
    ],
    "failed": [],
    "ok": true,
    "sources": [
      {
        "key": "manager",
        "label": "Web UI"
      },
      {
        "key": "haproxy",
        "label": "HAProxy"
      },
      {
        "key": "acme",
        "label": "acme.sh"
      },
      {
        "key": "keepalived",
        "label": "Keepalived"
      }
    ]
  },
  "notify": {
    "ok": true,
    "recent": [],
    "settings": {
      "destinations": [],
      "enabled": true,
      "events": {
        "apply": true,
        "certificates": true,
        "cluster": true,
        "updates": true,
        "watchdog": true
      },
      "min_severity": "warning",
      "repeat_hours": 6
    }
  },
  "peers": [],
  "preview": {
    "haproxy": "# Generated by haproxy-manager at 2026-08-11T02:23:25+00:00\n# Do not edit by hand -- changes are overwritten on Apply.\n\nglobal\n    log /dev/log local0\n    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners\n    stats timeout 30s\n    maxconn 4000\n    hard-stop-after 60s\n    ssl-default-bind-options ssl-min-ver TLSv1.2\n\ndefaults\n    log global\n    option dontlognull\n    option redispatch\n    retries 3\n    timeout connect 5s\n    timeout client 50s\n    timeout server 50s\n\nbackend bk_acme_challenge\n    mode http\n    server acme_sh 127.0.0.1:9080\n",
    "keepalived": "# Keepalived is disabled on this node (Cluster > This node)."
  },
  "services": [],
  "setup/state": {
    "complete": false,
    "has_peers": false,
    "has_services": false,
    "hostname": "293a0e497606",
    "interfaces": [
      {
        "addresses": [
          "172.17.0.3/16"
        ],
        "name": "eth0",
        "up": true
      },
      {
        "addresses": [],
        "name": "erspan0",
        "up": false
      },
      {
        "addresses": [],
        "name": "gre0",
        "up": false
      },
      {
        "addresses": [],
        "name": "gretap0",
        "up": false
      },
      {
        "addresses": [],
        "name": "ip6_vti0",
        "up": false
      },
      {
        "addresses": [],
        "name": "ip6gre0",
        "up": false
      },
      {
        "addresses": [],
        "name": "ip6tnl0",
        "up": false
      },
      {
        "addresses": [],
        "name": "ip_vti0",
        "up": false
      },
      {
        "addresses": [],
        "name": "sit0",
        "up": false
      },
      {
        "addresses": [],
        "name": "tunl0",
        "up": false
      }
    ],
    "needs_admin": false,
    "port": 8080,
    "suggested_url": "http://127.0.0.1:18062"
  },
  "stats": {
    "backends": [],
    "frontends": [],
    "generated": "2026-08-11T02:23:25+00:00",
    "ok": true
  },
  "status": {
    "acme_installed": true,
    "api_key_fp": "",
    "certs": [],
    "dirty": true,
    "edit_override": false,
    "haproxy": "activating",
    "hostname": "293a0e497606",
    "keepalived": "disabled",
    "latest_version": "",
    "peers": 0,
    "read_only": false,
    "read_only_reason": "",
    "renewal_note": "",
    "renews_here": true,
    "role": "standalone",
    "sync_available": true,
    "update_available": false,
    "version": "1.51.0",
    "vip_held": [],
    "vips": []
  },
  "update/log": {
    "log": "",
    "ok": true,
    "running": false,
    "version": "1.51.0"
  },
  "version": {
    "available": false,
    "can_update": false,
    "cannot_update_reason": "this node runs in a container -- pull a new image instead",
    "checked": "",
    "error": "",
    "latest": "",
    "ref": "main",
    "repo": "avandeputte/haproxy-manager",
    "updating": false,
    "version": "1.51.0"
  },
  "watchdog": {
    "enabled": true,
    "events": [],
    "last_run": "2026-08-11T02:23:24+00:00",
    "running": true,
    "self": {
      "detail": "",
      "ms": 0,
      "ok": true
    },
    "services": {
      "haproxy": {
        "checked": "2026-08-11T02:23:24+00:00",
        "detail": "the service is still starting",
        "state": "starting"
      },
      "keepalived": {
        "checked": "2026-08-11T02:23:24+00:00",
        "detail": "this node is not running Keepalived",
        "state": "disabled"
      }
    },
    "settings": {
      "enabled": true,
      "haproxy": true,
      "interval": 20,
      "keepalived": true,
      "max_restarts": 3,
      "window": 900
    },
    "systemd": false
  },
  "webui": {
    "certificate": "auto",
    "enabled": false,
    "exposed_directly": true,
    "listen": "0.0.0.0",
    "port": 8080,
    "rule_id": "",
    "url": ""
  },
  "whoami": {
    "admin_username": "a",
    "authenticated": true,
    "hostname": "293a0e497606",
    "needs_setup": false,
    "username": "a",
    "version": "1.51.0"
  }
};
globalThis.fetch = async (url) => {
  const path = String(url).replace(/^\/api\//, "").split("?")[0];
  const body = path in FIXTURES ? FIXTURES[path]
             : /^[a-z]+\/[a-z]+$/.test(path) ? []      /* a CRUD collection */
             : {};
  return { ok: true, status: 200, json: async () => body, text: async () => "" };
};

const root = process.cwd() + "/static/js/";
const { NAV, route } = await import(root + "shell.js");
await import(root + "main.js");          // wires the pages and renderers

let bad = 0, visited = 0;
for (const [key, label] of NAV) {
  if (key === "grp") continue;
  visited++;
  globalThis.location.hash = "#/" + key;
  const content = document.querySelector("#content");
  content.innerHTML = ""; content.children.length = 0;
  try { await route(); } catch (e) { /* route() catches its own */ }
  const shown = content.innerHTML + content.children.map(c => c.text || "").join("");
  // route() prints what a renderer threw, so look at the page rather than
  // waiting for an exception. TypeErrors count now that the fixtures above
  // give each page something sensible to render.
  const m = shown.match(/[A-Za-z_$][\w$]* is not defined|[A-Za-z_$][\w$.]* is not a function|Cannot read properties of (?:null|undefined)[^<"]*/);
  if (m) {
    bad++;
    console.log("  FAIL  " + (key || "(overview)").padEnd(26) + " " + m[0]);
  } else {
    console.log("  ok    " + (key || "(overview)").padEnd(26) + " " + label);
  }
}
console.log(bad ? "\n" + bad + " of " + visited + " pages reference something they do not have"
                : "\nall " + visited + " pages resolved every name they use");
process.exit(bad ? 1 : 0);
