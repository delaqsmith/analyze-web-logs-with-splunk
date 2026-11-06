
# 🔎 Analyze Web Logs with Splunk

### SIEM Deployment | Log Analysis | Security Monitoring | SPL

## 📖 Project Overview

This project demonstrates how Splunk Enterprise can be used as a Security Information and Event Management (SIEM) platform to collect, search, analyze, and visualize security-relevant log data.

Using Splunk's **Buttercup Games** sample dataset, I configured a local SIEM environment, ingested multiple log sources, and used Search Processing Language (SPL) to investigate web server activity and authentication events.

The project concludes with a **Security Monitor dashboard** that provides visibility into failed SSH login attempts, high-volume client IP addresses, and HTTP error responses.

The objective was to practice foundational Security Operations Center (SOC) workflows, including log ingestion, event filtering, security investigation, and dashboard development.

---

## 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| Splunk Enterprise | SIEM platform for log ingestion, searching, and visualization |
| Splunk Web | Web interface for managing searches and dashboards |
| Search Processing Language (SPL) | Query language for filtering and analyzing log events |
| Apache Access Logs | Web traffic and HTTP response analysis |
| SSH Authentication Logs | Failed login investigation |
| Buttercup Games Dataset | Sample log data used for security analysis |
| Classic Dashboards | Security monitoring visualizations |

---

## ✨ Project Features

- Configured a local Splunk environment for log analysis.
- Ingested web server, authentication, and transaction logs.
- Verified log indexing and field extraction.
- Used SPL to search for failed authentication events.
- Analyzed HTTP status codes and web server errors.
- Identified the most active client IP addresses.
- Aggregated failed SSH login attempts by source IP.
- Created a three-panel security monitoring dashboard.

---

## 🎯 What This Project Demonstrates

This project highlights practical SOC analyst skills in:

**SIEM Administration**
- Importing and indexing log data.
- Working with multiple log sources.
- Validating data availability and searchability.

**Security Log Analysis**
- Investigating authentication failures.
- Analyzing HTTP response patterns.
- Identifying unusual concentrations of network activity.

**Threat Hunting Fundamentals**
- Using SPL to filter security-relevant events.
- Aggregating activity by source IP address.
- Identifying patterns that warrant further investigation.

**Security Visualization**
- Building dashboards for operational visibility.
- Selecting appropriate visualization types.
- Converting raw log events into useful security metrics.

---

# 🔍 Investigation Process

## Step 1: Ingesting the Buttercup Games Dataset

### Objective

Populate the local Splunk environment with searchable log events for security analysis.

### Dataset

I used Splunk's official **Buttercup Games** tutorial dataset, which simulates activity from a fictional online retailer.

The dataset contains three primary log sources:

| Log File | Description |
|----------|-------------|
| `access.log` | Apache web server requests and HTTP responses |
| `secure.log` | SSH authentication activity |
| `vendor_sales.log` | Vendor purchase transaction records |

### Implementation

1. Downloaded `tutorialdata.zip` from Splunk's official documentation.
2. Opened Splunk Web at `http://localhost:8000`.
3. Navigated to **Settings → Add Data → Upload**.
4. Uploaded the compressed dataset without extracting it.
5. Configured the host assignment using **Segment in path**, with segment number `1`.
6. Reviewed the input settings and submitted the dataset for indexing.
7. Opened the Search & Reporting application to verify the imported events.

### Verification

After ingestion, I confirmed that Splunk could search events from the web access, SSH authentication, and vendor sales logs.

**Screenshot placeholder:**

![Indexed Buttercup Games Events](screenshots/01-indexed-events.png)

*Figure 1: Splunk search results displaying indexed Buttercup Games events.*

### Security Relevance

Correct log ingestion is a foundational SIEM requirement. Security investigations depend on having accessible, accurately indexed event data from relevant systems.

---

## Step 2: Exploring Log Events with SPL

### Objective

Use basic keyword and field-based searches to identify relevant events within the indexed data.

### Investigation A: Searching for Failure Events

I began with a wildcard keyword search:

```spl
fail*
```

This search returns events containing terms that begin with `fail`, including variations such as `failed` and `failure`.

**Purpose:**

Locate potentially relevant failure events across the available log sources.

**Screenshot placeholder:**

![Failure Keyword Search](screenshots/02-failure-keyword-search.png)

*Figure 2: Events returned by the wildcard failure search.*

### Investigation B: Identifying HTTP 404 Errors

Next, I searched for HTTP 404 responses:

```spl
status=404
```

HTTP 404 responses indicate that a requested resource was not found.

**Security significance:**

Repeated requests for nonexistent pages can be associated with:

- Broken links or outdated resources.
- Automated web crawlers.
- Vulnerability scanning.
- Attempts to discover hidden files or directories.

A 404 response alone is not evidence of malicious activity. Additional context, such as request frequency, URLs, and source IP addresses, is necessary.

**Screenshot placeholder:**

![HTTP 404 Search](screenshots/03-http-404-search.png)

*Figure 3: Web log events containing HTTP 404 responses.*

---

## Step 3: Analyzing HTTP Status Codes

### Objective

Aggregate web server response codes to understand request outcomes and identify error patterns.

### SPL Query

```spl
source="tutorialdata.zip:*/access.log"
| stats count by status
```

### Query Breakdown

- `source` restricts the search to Apache access logs.
- `stats count` calculates the number of matching events.
- `by status` groups the results by HTTP status code.

### Analysis

This query produces a summary of HTTP responses, allowing the distribution of successful requests, redirects, client errors, and server errors to be examined.

HTTP status codes can provide useful indicators:

| Status Code | Meaning | Security Relevance |
|-------------|---------|-------------------|
| 200 | OK | Successful web request |
| 301/302 | Redirect | Redirect behavior |
| 403 | Forbidden | Access denied |
| 404 | Not Found | Requests for unavailable resources |
| 500 | Internal Server Error | Server-side processing failure |

High concentrations of errors can help identify activity requiring investigation, although they can also result from normal application behavior.

**Screenshot placeholder:**

![HTTP Status Code Statistics](screenshots/04-http-status-statistics.png)

*Figure 4: Aggregated HTTP status code counts from Apache access logs.*

---

## Step 4: Identifying High-Volume Client IP Addresses

### Objective

Determine which client IP addresses generated the highest number of web requests.

### SPL Query

```spl
source="tutorialdata.zip:*/access.log"
| stats count by clientip
| sort -count
| head 10
```

### Query Breakdown

1. Filters events to Apache access logs.
2. Counts requests associated with each client IP.
3. Sorts results by request count in descending order.
4. Returns the ten most active IP addresses.

### Analysis

This search identifies the highest-volume sources of web traffic.

In a SOC environment, unusually high request counts may justify investigation for:

- Automated scanning.
- Bot-generated requests.
- Repeated resource enumeration.
- Unexpected traffic spikes.

However, high request volume alone does not establish malicious intent. Legitimate crawlers, proxies, and frequently used services can generate similar patterns.

**Screenshot placeholder:**

![Top Client IP Addresses](screenshots/05-top-client-ips.png)

*Figure 5: Top ten client IP addresses ranked by web request volume.*

---

## Step 5: Investigating Failed SSH Login Attempts

### Objective

Examine SSH authentication failures and identify source IP addresses associated with repeated unsuccessful login attempts.

### Investigation A: Finding Failed Password Events

I searched the SSH authentication logs for failed password attempts:

```spl
source="tutorialdata.zip:*/secure.log" "Failed password"
```

The quoted phrase ensures that Splunk searches for the exact text `Failed password`.

### Analysis

Failed SSH login events can provide information about unsuccessful access attempts, including usernames and originating IP addresses where those fields are available.

A pattern of repeated failures may indicate:

- Incorrect credentials.
- Misconfigured automated processes.
- Password guessing.
- Potential brute-force activity.

**Screenshot placeholder:**

![Failed SSH Login Events](screenshots/06-failed-ssh-events.png)

*Figure 6: SSH authentication events containing failed password attempts.*

### Investigation B: Counting Failed Logins by Source IP

I expanded the search to aggregate failed attempts by originating IP address.

```spl
source="tutorialdata.zip:*/secure.log" "Failed password"
| stats count by src_ip
```

### Query Breakdown

- Filters authentication logs for failed password events.
- Groups the events by `src_ip`.
- Counts the number of failures associated with each IP address.

### Security Significance

Grouping authentication failures by source IP helps identify systems generating repeated unsuccessful login attempts.

This is useful for investigating potential brute-force behavior and prioritizing IP addresses for further review.

Additional evidence, including timestamps, targeted accounts, successful logins, and known administrative activity, would be required to determine whether the failures represent an attack.

**Screenshot placeholder:**

![Failed Login Attempts by Source IP](screenshots/07-failed-logins-by-ip.png)

*Figure 7: Failed SSH login attempts aggregated by source IP address.*

---

# 📊 Building the Security Monitor Dashboard

## Step 6: Creating the Dashboard

### Objective

Consolidate important security indicators into a single monitoring interface.

I created a dashboard titled **Security Monitor** using Splunk's Classic Dashboard framework.

### Configuration

- **Dashboard Name:** Security Monitor
- **Dashboard Type:** Classic Dashboard
- **Permissions:** Private
- **Time Range:** Last 7 Days
- **Total Panels:** 3

The dashboard was designed to display authentication failures, high-volume web traffic sources, and HTTP error distributions.

---

## Panel 1: Failed Logins

**Visualization:** Single Value

### SPL Query

```spl
source="tutorialdata.zip:*/secure.log" "Failed password"
| stats count AS "Failed Logins"
```

### Purpose

Displays the total number of failed SSH login events within the selected time range.

### Security Value

Provides a quick overview of authentication failures that may require closer investigation.

![Failed Logins Dashboard Panel](screenshots/08-failed-logins-panel.png)

*Figure 8: Single-value visualization displaying total failed login attempts.*

---

## Panel 2: Top 10 Client IPs

**Visualization:** Bar Chart

### SPL Query

```spl
source="tutorialdata.zip:*/access.log"
| stats count by clientip
| sort -count
| head 10
```

### Purpose

Ranks client IP addresses according to the number of web requests generated.

### Security Value

Helps analysts identify high-volume traffic sources and prioritize unusual activity for further review.

![Top Client IPs Dashboard Panel](screenshots/09-top-client-ips-panel.png)

*Figure 9: Bar chart showing the ten most active client IP addresses.*

---

## Panel 3: HTTP Errors by Status Code

**Visualization:** Pie Chart

### SPL Query

```spl
source="tutorialdata.zip:*/access.log" status>=400
| stats count by status
```

### Purpose

Displays the distribution of HTTP client and server error responses.

### Security Value

Helps analysts recognize which HTTP errors are most common and identify patterns that may warrant investigation.

The chart shows the **proportion of error events by status code**, rather than an overall HTTP error rate.

![HTTP Error Distribution Dashboard Panel](screenshots/10-http-error-panel.png)

*Figure 10: Pie chart displaying HTTP errors grouped by status code.*

---

## 🖥️ Completed Security Monitor Dashboard

The completed dashboard brings together three security indicators:

| Panel | Visualization | Monitored Activity |
|-------|---------------|-------------------|
| Failed Logins | Single Value | Total unsuccessful SSH logins |
| Top 10 Client IPs | Bar Chart | Highest-volume web request sources |
| HTTP Errors by Status Code | Pie Chart | Distribution of HTTP error responses |

Together, these panels provide a centralized view of authentication and web traffic activity within the sample dataset.

**Final dashboard screenshot:**

![Completed Security Monitor Dashboard](screenshots/11-security-monitor-dashboard.png)

*Figure 11: Completed Splunk Security Monitor dashboard.*

---

## 📚 What I Learned

### 1. Log Ingestion Is the Foundation of SIEM Monitoring

Before meaningful analysis can occur, logs must be collected, indexed, and made searchable.

This project reinforced the importance of validating log sources before beginning an investigation.

### 2. SPL Converts Raw Events into Actionable Information

Individual log entries provide limited context.

By combining filtering, aggregation, and sorting commands, I was able to summarize activity and identify patterns more efficiently.

### 3. Authentication Logs Are Valuable for Threat Detection

Failed SSH login events can reveal patterns associated with password guessing and potential brute-force attempts.

Grouping these events by source IP provides a starting point for investigating suspicious authentication activity.

### 4. Web Logs Provide Important Security Context

HTTP response codes and request volume can help analysts identify unusual behavior, including repeated resource requests and concentrations of errors.

These indicators are most useful when combined with additional context rather than interpreted in isolation.

### 5. Dashboards Improve Security Visibility

A dashboard makes it easier to review multiple security metrics without manually executing each search.

This project demonstrated how to transform SPL search results into a centralized monitoring interface.

---

## 🚀 Potential Improvements

The project establishes a foundation for more advanced SIEM monitoring. Future improvements could include:

### 1. Automated Security Alerts

Configure Splunk alerts for unusual increases in failed authentication attempts or HTTP errors.

### 2. Failed Login Trend Analysis

Create time-based visualizations to identify authentication failure spikes and recurring patterns.

### 3. IP Reputation Enrichment

Integrate threat intelligence to provide additional context about suspicious source IP addresses.

### 4. Cross-Source Event Correlation

Correlate authentication failures with web traffic activity to investigate potentially related events.

### 5. Additional Detection Use Cases

Expand the dashboard to monitor:

- HTTP 403 and 404 spikes.
- Repeated requests to sensitive URL paths.
- Authentication failures followed by successful logins.
- Unusual request patterns from individual IP addresses.

### 6. Dashboard Time Controls

Add shared time-range inputs to support more flexible historical investigations.

---

## 🏁 Conclusion

This project provided hands-on experience with SIEM deployment, log ingestion, SPL querying, authentication event investigation, web traffic analysis, and security dashboard development.

By analyzing Apache web access logs and SSH authentication events, I practiced identifying security-relevant patterns and organizing investigative results into a centralized monitoring dashboard.

These skills are directly applicable to entry-level SOC analyst responsibilities involving security event monitoring, log analysis, and incident triage.

---
