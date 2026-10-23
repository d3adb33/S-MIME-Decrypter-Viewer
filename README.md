# Technical Specification & Architecture Guide
## S/MIME EML Decrypter & Direct Viewer (Client-Side Web Application)

---

## 1. System Overview

The **S/MIME EML Decrypter & Direct Viewer** is an enterprise-grade, zero-trust web application built to process, decrypt, parse, and display S/MIME encrypted E-Mail files (`.eml`, `smime.p7m`) directly within modern web browsers. 

Designed specifically as a utility for **Google Workspace** environments, it addresses a specific compatibility challenge: **Multi-wrapped / Nested S/MIME structures** (e.g., Dual-Wrapping and RFC 2634 / RFC 5751 Triple-Wrapping) originating from legacy systems or external enterprise mail gateways that cannot be natively rendered by the standard Gmail web interface.

### Key Capabilities
* **100% Client-Side Execution:** Cryptographic keys and decrypted data remain exclusively in local browser RAM. No payload or credential is ever transmitted over the network.
* **PKCS#12 & PEM Support:** Parses `.p12` / `.pfx` credential stores as well as separate RSA `.key` and `.crt` files directly in JavaScript.
* **Multi-Layer Unwrapping:** Recursively unrolls nested Cryptographic Message Syntax (CMS) / PKCS#7 `EnvelopedData` envelopes.
* **Full MIME Parsing & Inline Rendering:** Automatically decodes Quoted-Printable, Base64, and multi-part MIME structures, rendering HTML emails safely inside a sandboxed `iframe` with [DOMPurify](https://github.com/cure53/DOMPurify) sanitization.
* **Attachment Extraction:** Decodes and allows individual downloads of email attachments.

---

## 2. High-Level Architecture & Zero-Trust Security Model

```
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                       LOCAL BROWSER SANDBOX (RAM)                        │
 │                                                                         │
 │  ┌───────────────────┐    ┌───────────────────┐    ┌─────────────────┐  │
 │  │ PKCS#12 Bundle    │    │ Encrypted EML     │    │ Cryptographic   │  │
 │  │ (.p12 / .pfx)     │    │ (.eml / .p7m)     │    │ Engine          │  │
 │  └─────────┬─────────┘    └─────────┬─────────┘    │ (Node-Forge JS) │  │
 │            │                        │              └────────┬────────┘  │
 │            ▼                        ▼                       │           │
 │  ┌────────────────────────────────────────────┐             │           │
 │  │ Private RSA Key Extraction & Validation    ├─────────────┤           │
 │  └────────────────────────────────────────────┘             │           │
 │                                                             ▼           │
 │  ┌───────────────────────────────────────────────────────────┐          │
 │  │ Recursive CMS / PKCS#7 Unwrapping Engine                  │          │
 │  │ (Resolves Dual & Triple Wrapped Envelopes)                │          │
 │  └──────────────────────────┬────────────────────────────────┘          │
 │                             │                                           │
 │                             ▼                                           │
 │  ┌───────────────────────────────────────────────────────────┐          │
 │  │ MIME Parser & HTML Sanitizer (DOMPurify)                  │          │
 │  └──────────────────────────┬────────────────────────────────┘          │
 │                             │                                           │
 │                             ▼                                           │
 │  ┌───────────────────────────────────────────────────────────┐          │
 │  │ Direct In-Browser Viewer & Attachment Extractor           │          │
 │  └───────────────────────────────────────────────────────────┘          │
 └─────────────────────────────────────────────────────────────────────────┘
                                   │
                           X NO NETWORK CALLS
                                   │
                                   ▼
                            [ INTERNET / GCP ]
```

### Security Guarantees
1. **Zero Data Exfiltration:** All operations execute within the client V8 JavaScript engine. The application operates offline once assets are cached.
2. **Key Isolation:** Passphrases unlock PKCS#12 keybags strictly in-memory. Private keys are never saved to `localStorage`, `sessionStorage`, or IndexedDB.
3. **XSS Mitigation:** HTML email bodies are sanitized via DOMPurify before injection into an isolated, sandboxed `<iframe>` (`sandbox="allow-same-origin"`).

---

## 3. Cryptographic Engine & Handling Multi-Wrapped S/MIME

### Standard S/MIME vs. Nested Multi-Wrapping
Standard S/MIME ([RFC 5751](https://tools.ietf.org/html/rfc5751)) encapsulates MIME entities in a single CMS structure (e.g., `SignedData` or `EnvelopedData`). 

However, complex enterprise workflows use nested layers:
* **Dual Wrapping:** Signed $\rightarrow$ Encrypted $\rightarrow$ Signed.
* **Triple Wrapping (RFC 2634):** Compressed $\rightarrow$ Signed $\rightarrow$ Encrypted $\rightarrow$ Signed.

When Gmail's server-side parser encounters non-standard or deeply nested `application/pkcs7-mime` structures, it may display the payload as an unparseable `smime.p7m` attachment.

### Unwrapping Execution Loop
The web application addresses this by employing a recursive unwrapping engine:

```javascript
// Conceptual logic of the unwrapping engine
let currentPayload = rawEmlText;
let unwrappedLayers = 0;

while (unwrappedLayers < 5) {
    let p7b64Data = extractPKCS7FromEML(currentPayload);
    if (!p7b64Data) break; // Innermost raw MIME payload reached

    const derBytes = forge.util.decode64(p7b64Data);
    const asn1 = forge.asn1.fromDer(derBytes);
    const msg = forge.pkcs7.messageFromAsn1(asn1);

    // Decrypt symmetric content key using client RSA Private Key
    msg.decrypt(msg.recipients[0], privateKey);
    
    currentPayload = msg.content.getBytes();
    unwrappedLayers++;
}

// Proceed to full MIME structure parsing
parseAndDisplayEmail(currentPayload);
```

---

## 4. Architectural Comparison: Web App vs. Gmail Add-on vs. Email Gateway

| Feature / Criteria | **Client-Side Web App** *(This Tool)* | **Gmail Add-on** *(Apps Script + GCP)* | **Secure Mail Gateway** *(e.g., SEPPMAIL / NoSpamProxy)* |
| :--- | :--- | :--- | :--- |
| **Primary Deployment Use Case** | Ad-hoc decryption & key-user utility | Automated workflow within Gmail UI | Centralized Enterprise Infrastructure |
| **Key Storage** | User-loaded on demand (In-Memory) | GCP Secret Manager / KMS | Centralized HSM / Gateway Key Store |
| **Multi-Wrapping Support** | **Full** (Recursive JS Engine) | **Full** (via GCP Cloud Function) | **Full** (Appliance Engine) |
| **Client Overhead** | None (Runs in Web Browser) | None (Google Workspace Panel) | None (Decrypted at Inbound Relay) |
| **Implementation Complexity** | **Low** (Single HTML File) | **Medium** (Apps Script + Cloud Function) | **High** (MX Routing & Infrastructure) |
| **Google Best Practice Match** | Exceptional for ad-hoc inspection | Recommended for automated Workspace Add-ons | Recommended for company-wide S/MIME |

---

## 5. Enterprise Deployment Options

Because the application is fully self-contained in a single `.html` file with embedded styling and JavaScript dependencies, it can be deployed via multiple enterprise patterns:

### Option A: Static Hosting via Google Cloud Storage + Cloud CDN
Deploy the HTML file to a static Google Cloud Storage bucket fronted by Cloud CDN for high availability.
* **Google Doc Reference:** [Hosting a static website on Google Cloud Storage](https://cloud.google.com/storage/docs/hosting-static-website)

### Option B: Internal Deployment via Google Cloud Run
Package the static application using Nginx in a micro-container and deploy it to Google Cloud Run, leveraging **Identity-Aware Proxy (IAP)** for Google Workspace SSO protection.
* **Google Doc Reference:** [Cloud Run Documentation](https://cloud.google.com/run/docs)
* **Google Doc Reference:** [Overview of Identity-Aware Proxy](https://cloud.google.com/iap/docs/concepts-overview)

### Option C: Direct Distribution via Google Drive
Distribute the single file to authorized Security Analysts or Key Users via Google Drive with restricted view permissions.

---

## 6. Official Google Documentation & Best Practice Links

To ensure compliance with Google Workspace migration and security standards, consult the following official documentation:

* **Google Workspace Hosted S/MIME Overview:**  
  [Enable Hosted S/MIME for Message Encryption](https://support.google.com/a/answer/6374482)
* **Google Workspace Client-Side Encryption (CSE):**  
  [Set up Client-Side Encryption for Gmail](https://support.google.com/a/answer/10740391)
* **Inbound Mail Routing & Gateways:**  
  [Set up an Inbound Mail Gateway in Google Workspace](https://support.google.com/a/answer/60730)
* **Google Apps Script & Card Service Development:**  
  [Building Gmail Add-ons with Google Apps Script](https://developers.google.com/workspace/add-ons/gmail)
* **GCP Cloud Functions Authentication:**  
  [Authenticating Developers and Apps in Cloud Functions](https://cloud.google.com/functions/docs/securing/authenticating)
* **GCP Secret Manager:**  
  [Secret Manager Documentation](https://cloud.google.com/secret-manager/docs)
