# Acme Health - Capstone Project Write-up

# Acme Health - Capstone Project Personal Write-up
**Candidate:** Jose Fabio Navarro Mora
**Certification Level:** CGE-P Candidate  
**Target Application:** Patient Intake API  
**Chosen Compliance Framework:** SOC 2 Type II (Security and Availability)

---

## 1. Introduction, Design Decisions & Why I Chose SOC 2

### 1.1 Hello, this is my project!
In this project, I took a "starter kit" code repository for a telehealth company called Acme Health (which has about 50 employees) and worked on fixing its security and infrastructure. When I first looked at the code, it was a bit of a mess from a security point of view: it had cloud databases and storage buckets without encryption, and anyone or any script could access everything because the permissions were too wide.

As a Senior GRC Analyst learning about GRC Engineering, my job was to build a protective wrapper around this application. I wanted to make sure that every time code is pushed to GitHub, it automatically checks for security issues, signs the proof that everything is okay, and saves that evidence in a safe place.

### 1.2 Why I Chose SOC 2 Type II instead of other frameworks
When I started, I had to choose a security framework. I looked at options like NIST SP 800-53 and ISO 27001, but they felt way too heavy for a 50-person startup:
* **NIST SP 800-53:** This is what the US government uses. It has hundreds of super strict controls. If I tried to implement this here, the engineering team wouldn't be able to ship a single line of features because of the massive bureaucratic overhead.
* **ISO 27001:** This is great for big corporate paperwork, meetings, and policies, but it doesn't give you direct, practical examples of how to configure an AWS database or an S3 bucket safely.

I chose **SOC 2 Type II (Security and Availability)** because it is the industry standard for cloud startups. It focuses on practical things: making sure patient data is safe from unauthorized people (Security) and making sure the API doesn't crash so doctors can use it (Availability). Implementing SOC 2 directly inside our GitHub pipeline means we prove compliance automatically with code, which is exactly what corporate clients ask for before buying software from a startup.

---

## 2. Gaps Found and How I Fixed Them in Terraform

I went through the `GAPS.md` file in the starter kit and picked 5 critical security holes to fix. Here is what I did in plain English inside the `main.tf` file:

### GAP-01: S3 Uploads Bucket Encryption (SOC 2 CC6.1 - Data Protection)
* **The Problem:** The bucket where patients upload files was open and unencrypted at rest. If someone managed to access AWS storage, they could read patient files like an open book.
* **My Fix:** I created a Customer-Managed Key (CMK) using AWS KMS. I also turned on automatic key rotation every year. Then, I updated the S3 bucket configuration to force it to use this specific key. Now, data is automatically scrambled the second it hits the disk.

### GAP-02: DynamoDB Table Encryption (SOC 2 CC6.1 - Data Protection)
* **The Problem:** The database storing active patient forms was using standard AWS-owned keys. This works, but we don't control the key lifecycle.
* **My Fix:** I modified the `aws_dynamodb_table.intake` resource block to explicitly use our new KMS key instead of the generic AWS one. Now, our company has full cryptographic control over the database data.

### GAP-03: Blocking Non-Secure Connections (SOC 2 CC6.7 - Secure Transmission)
* **The Problem:** The bucket was allowing normal `http://` requests, which means hackers could potentially intercept patient data in transit through a Man-in-the-Middle attack.
* **My Fix:** I wrote an explicit S3 Bucket Policy with a `Deny` statement. It basically says: "If the connection is NOT using secure HTTPS (`aws:SecureTransport == false`), block the request immediately."

### GAP-04: S3 Bucket Versioning and Integrity (SOC 2 A1.2 - Availability)
* **The Problem:** If an engineer accidentally deleted a patient file, or if ransomware hit the bucket, the files would be gone forever.
* **My Fix:** I added an `aws_s3_bucket_versioning` resource to make it append-only. If someone deletes a file, AWS just puts a "delete marker" on top, but the old versions remain safe underneath so we can recover them instantly.

### GAP-07: Cleaning up the Lambda Permissions (SOC 2 CC6.3 - Access Modification)
* **The Problem:** The backend Lambda function had a wildcard policy (`dynamodb:*` and `s3:*`). This meant that if someone hacked the Lambda function, they could delete our entire database.
* **My Fix:** I deleted the wildcards and changed the permissions to use specific actions like `dynamodb:PutItem` and `s3:PutObject`. Now, the Lambda function can only do exactly what it needs to do to work, nothing more.

---

## 3. My GitHub Actions Pipeline and Real Problems Faced

### 3.1 The 5 Required Steps
To automate everything, I built a workflow file named `.github/workflows/grc-gate.yml`. The rubric required exactly five named steps to process the code in order:
1. **Plan:** It runs `terraform plan` and turns the output into a JSON file so that other tools can read it.
2. **Policy Check:** It installs Open Policy Agent (OPA) and scans that JSON file to make sure no engineer is trying to deploy an unencrypted bucket.
3. **Apply:** If OPA says the code is safe, it deploys the infrastructure.
4. **Sign:** It uses a tool called Cosign to sign a cryptographic proof file showing that this specific deployment was checked and approved.
5. **Upload:** It uploads that signature file (`compliance-evidence.sig`) to our Object-Locked S3 vault for auditors to see.

### 3.2 Sincere Tooling Trade-offs & Troubles I Ran Into
Since I am learning how to use these tools, I ran into real problems that I had to solve, forcing me to change how the pipeline works:

* **The OPA Network Failure (`curl` vs. Official Actions):** Originally, I copied a tutorial that downloaded the OPA tool using a manual `curl` command from the internet. During my pipeline runs, this step randomly failed with a `curl: (56) Failure when receiving data from the peer` error and froze for 5 minutes. I realized that relying on downloading files via `curl` makes the pipeline unstable if remote servers experience blips. To fix this, I completely replaced the manual script with the official GitHub Action `open-policy-agent/setup-opa@v2`. This made the step stable, secure, and reduced the setup time to just 3 seconds.
* **Cosign Offline Mode (`--tlog-upload=false`):** By default, Cosign tries to upload code-signing records to a public internet transparency log called Rekor. But because we are a healthcare company handling private patient information, uploading details about our private infrastructure to a public ledger is a bad idea. I made a conscious trade-off to add the `--tlog-upload=false` flag. This keeps our security audits 100% private and inside our company perimeter.

---

## 4. OPA Policies and How I Tested Them

To make the **Policy Check** work, I wrote rules using a language called Rego in `soc2_security.rego`.

### 4.1 How the policies work
The Rego script reads the JSON file from our Terraform Plan. It loops through all the resources we are trying to create. For example, it checks if a database table has encryption turned on. If it finds a resource that violates our rules, it triggers a `deny` message that breaks the GitHub pipeline and shows an error like: *"DynamoDB Table must use our KMS CMK key!"*

### 4.2 How I tested my policies
To be absolutely sure my rules worked, I wrote a separate file called `soc2_security_test.rego` to run unit tests on my policy. 
* I created a **Mock Compliant Plan** (a fake plan that is perfectly configured) and tested that OPA allowed it through (`count(deny) == 0`).
* I created a **Mock Non-Compliant Plan** (an intentionally broken plan with missing encryption) and verified that OPA caught it and blocked it.
Running `opa test` ensures that if our security rules are ever modified or accidentally broken, the tests will catch the mistake immediately.

---

## 5. OSCAL Integration (Connecting Code to Compliance)

One of the hardest parts for me to understand at first was OSCAL (`component-definition.json`). Usually, security compliance means writing a 100-page Word document that nobody reads and that becomes outdated the next day. 

OSCAL (Open Security Controls Assessment Language) fixes this by turning compliance into a machine-readable JSON file. I structured our file using the official **OSCAL 1.1.0 schema**. 

Inside the JSON file, I explicitly mapped our real-world components (like our `Acme Health Secure Infrastructure`) directly to the SOC 2 control ID `CC6.1`. This creates a digital link: the auditor doesn't need to log into my AWS console to see if the database is encrypted; they can just use an automated compliance tool to read our OSCAL file and verify that our automated pipeline checks match our official security framework policies.

---

## 6. What I Didn't Get to Do

Because this is a laboratory environment and I had to work through network issues, platform restrictions, and learning curves, there are several things I could not finish. This is my honest backlog for future improvements:

1. **Hardware Security Modules (HSM) for Keys:** Right now, during the `Sign` stage, Cosign generates local, temporary file-based keys on the fly using an environment variable password. In a mature company, this is a risk because environment passwords can leak. In the future, I want to store these signing certificates inside a real cloud hardware security module, like AWS KMS HSM, so nobody can ever see or copy the private key.
2. **Handling Organization Workflow Approvals:** When opening Pull Requests from my personal account to the organization repository, GitHub flags the workflow as *"Awaiting approval from a maintainer"*. Because I do not have administrative privileges over the core organization organization runners, I had to do my primary testing and validation runs offline and in direct branch pushes. In a real corporate setup, I would need to work with the DevOps team to pre-approve developer forks or use self-hosted enterprise runners to avoid this approval bottleneck.

