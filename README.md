FortiNDR Cloud Application for Splunk SOAR
==========================================

Publisher: Fortinet Inc.
Contributors: N/A
App Version: 1.0.0
Product Vendor: Fortinet Inc.
Product Name: FortiNDR Cloud
Product Version Supported (regex): ".*"
Latest Tested Versions:

This app allows the use of the information provided by the FortiNDR Cloud Service to perform containment and investigative actions on Splunk SOAR.

tr.plain th { text-align: center; }

### Configuration Variables

The below configuration variables are required for this App to operate on **FortiNDR Cloud**. These are specified when configuring an asset in Splunk SOAR.

| VARIABLE | REQUIRED | TYPE | DESCRIPTION |
| --- | --- | --- | --- |
| **muted** | optional | boolean | Set to true to include muted detections. Default to false |
| **api_key** | required | password | API Token to connect to FortiNDR Cloud RESTful APIs. |
| **first_poll** | optional | string | First Poll (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). |
| **muted_rule** | optional | boolean | Set to true to include muted rules. Default to false |
| **account_uuid** | optional | string | Account UUID to filter retrieved detections |
| **api\_base\_url** | required | string | Provide the Base URL to access the APIs by replacing the &lt;Region&gt; and &lt;Domain&gt; in https://&lt;API&gt;-&lt;Region&gt;.&lt;Domain&gt;/ with the appropriate value. |
| **muted_device** | optional | boolean | Set to true to include muted devices. Default to false |
| **polling_delay** | optional | numeric | Polling delay in minute. This is required to allow time for the detections to be added before polling them. |

### Supported Actions

[fortindr create detection rule](#action-fortindr-create-detection-rule) - Create a new detection rule.
[fortindr get detection events](#action-fortindr-get-detection-events) - Get a list of the events associated with a specific detection.
[fortindr get detection rule events](#action-fortindr-get-detection-rule-events) - Get a list of the events that matched on a specific rule.
[fortindr resolve detection](#action-fortindr-resolve-detection) - Resolve a specific detection.
[fortindr get detection rules](#action-fortindr-get-detection-rules) - Get a list of detection rules.
[fortindr get detections](#action-fortindr-get-detections) - Get information about the detections.
[fortindr get entity file](#action-fortindr-get-entity-file) - Get information about a file.
[fortindr get entity dhcp](#action-fortindr-get-entity-dhcp) - Get DHCP information about an IP address.
[fortindr get entity pdns](#action-fortindr-get-entity-pdns) - Get passive DNS information about an IP or domain.
[fortindr get entity summary](#action-fortindr-get-entity-summary) - Get summary information about an IP or domain.
[fortindr get telemetry network](#action-fortindr-get-telemetry-network) - Get network telemetry data grouped by time.
[fortindr get telemetry packetstats](#action-fortindr-get-telemetry-packetstats) - Get packetstats telemetry data grouped by time.
[fortindr get telemetry events](#action-fortindr-get-telemetry-events) - Get event telemetry data grouped by time.
[fortindr create task](#action-fortindr-create-task) - Create a new PCAP task.
[fortindr get tasks](#action-fortindr-get-tasks) - Get a list of all the PCAP tasks.
[fortindr get devices](#action-fortindr-get-devices) - Get a list of all devices.
[fortindr get sensors](#action-fortindr-get-sensors) - Get a list of all sensors.
[on poll](#action-on-poll) - Retrieve latest Detections from the FortiNDR Cloud Service.
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration

action: 'fortindr create detection rule'
----------------------------------------

Create a new detection rule.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **name** | required | The name of the rule. | string |     |
| **category** | required | The category of the rule. | string |     |
| **severity** | required | The severity of the rule. | string |     |
| **confidence** | required | The confidence of the rule. | string |     |
| **description** | optional | A description for the rule. | string |     |
| **specificity** | optional | Specificity | string |     |
| **account_uuid** | required | Account where the rule will be created. | string |     |
| **query_signature** | required | The IQL query for the rule. | string |     |
| **device\_ip\_fields** | optional | List, seaprated by ',', of the fields to check for impacted devices. Using 'DEFAULT' if not provided. (allows comma-separated lists) | string |     |
| **indicator_fields** | optional | List, separated by ',' of the indicator's fields. (allows comma-separated lists) | string |     |
| **primary\_attack\_id** | optional | Primary Attack ID | string |     |
| **run\_account\_uuids** | required | Account UUIDs on which this rule will run. This will usually be just your own account UUID. (separate multiple accounts by comma) (allows comma-separated lists) | string |     |
| **secondary\_attack\_id** | optional | Secondary Attack ID | string |     |
| **auto\_resolution\_minutes** | optional | The number of minutes after which detections will be auto-resolved. If 0 then detections have to be manually resolved. | numeric |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Detection Rule created successfully. |
| action_result.data.*.rule.uuid | string |     | 55f39b72-2622-4137-9051-bc2ff364f059 |
| action\_result.data.*.rule.account\_uuid | string |     | 55f39b72-2622-4137-9051-bc2ff364f059 |
| action\_result.data.*.rule.shared\_account_uuids | string |     | 55f39b72-2622-4137-9051-bc2ff364f059 |
| action\_result.data.*.rule.run\_account_uuids | string |     | \["55f39b72-2622-4137-9051-bc2ff364f059"\] |
| action_result.data.*.rule.name | string |     | AR T1595 |
| action_result.data.*.rule.category | string |     | Attack:Infection Vector |
| action\_result.data.*.rule.query\_signature | string |     | ip IN ('1.1.1.1','2.2.2.2') AND event_type = 'dns' |
| action_result.data.*.rule.description | string |     |     |
| action_result.data.*.rule.severity | string |     | high  <br>moderate  <br>low |
| action_result.data.*.rule.confidence | string |     | high  <br>moderate  <br>low |
| action\_result.data.*.rule.auto\_resolution_minutes | numeric |     | 10080 |
| action_result.data.*.rule.enabled | boolean |     | true  <br>false |
| action\_result.data.*.rule.created\_user_uuid | string |     | 55f39b72-2622-4137-9051-bc2ff364f059 |
| action_result.data.*.rule.created | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.rule.updated\_user_uuid | string |     | 55f39b72-2622-4137-9051-bc2ff364f059 |
| action_result.data.*.rule.updated | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.rule.critical\_updated | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.rule.primary\_attack_id | string |     |     |
| action\_result.data.*.rule.secondary\_attack_id | string |     |     |
| action_result.data.*.rule.specificity | string |     |     |
| action\_result.data.*.rule.rule\_accounts | string |     |     |
| action\_result.data.*.rule.device\_ip_fields | string |     | DEFAULT |
| action\_result.data.*.rule.indicator\_fields | string |     | src.ip |
| action\_result.data.*.rule.source\_excludes | string |     | Zscaler |

action: 'fortindr get detection events'
---------------------------------------

Get a list of the events associated with a specific detection.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **limit** | optional | The number of records to return, default: 100, max: 1000. | numeric |     |
| **offset** | optional | The number of records to skip past. | numeric |     |
| **detection_uuid** | required | Detection uuid to filter by. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Detection Events retrieved successfully. |
| action\_result.data.*.detection\_events.*.src_ip | string |     | 8.8.8.8 |
| action\_result.data.*.detection\_events.*.dst_ip | string |     | 9.9.9.9 |
| action\_result.data.*.detection\_events.*.src_port | numeric |     | 53  |
| action\_result.data.*.detection\_events.*.dst_port | numeric |     | 32  |
| action\_result.data.*.detection\_events.*.host_domain | string |     |     |
| action\_result.data.*.detection\_events.*.flow_id | string |     | Cpv6xc2a3gA6fA8WE |
| action\_result.data.*.detection\_events.*.event_type | string |     | dns |
| action\_result.data.*.detection\_events.*.sensor_id | string |     | sen1 |
| action\_result.data.*.detection\_events.*.timestamp | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.detection\_events.*.customer_id | string |     | gig |
| action\_result.data.*.detection\_events.*.detection_uuid | string |     | a7015381-0484-11ee-a43f-067ff9e63f5b |
| action\_result.data.*.detection\_events.*.rule_uuid | string |     | a7015381-0484-11ee-a43f-067ff9e63f5b |
| action\_result.data.*.detection\_events.*.uuid | string |     | a7015381-0484-11ee-a43f-067ff9e63f5b |

action: 'fortindr get detection rule events'
--------------------------------------------

Get a list of the events that matched on a specific rule.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **limit** | optional | The number of records to return, default: 100, max: 1000. | numeric |     |
| **offset** | optional | The number of records to skip past. | numeric |     |
| **rule_uuid** | required | Rule UUID to get events for | string |     |
| **account_uuid** | optional | Account uuid to filter by. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Detection Rule Events retrieved successfully. |
| action\_result.data.*.detection\_rule\_event.src\_ip | string |     | 8.8.8.8 |
| action\_result.data.*.detection\_rule\_event.dst\_ip | string |     | 9.9.9.9 |
| action\_result.data.*.detection\_rule\_event.src\_port | numeric |     | 53  |
| action\_result.data.*.detection\_rule\_event.dst\_port | numeric |     | 32  |
| action\_result.data.*.detection\_rule\_event.host\_domain | string |     |     |
| action\_result.data.*.detection\_rule\_event.flow\_id | string |     | Cpv6xc2a3gA6fA8WE |
| action\_result.data.*.detection\_rule\_event.event\_type | string |     | dns |
| action\_result.data.*.detection\_rule\_event.sensor\_id | string |     | sen1 |
| action\_result.data.*.detection\_rule_event.timestamp | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.detection\_rule\_event.customer\_id | string |     | gig |
| action\_result.data.*.detection\_rule_event.uuid | string |     | a7015381-0484-11ee-a43f-067ff9e63f5b |

action: 'fortindr resolve detection'
------------------------------------

Resolve a specific detection.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **resolution** | required | Resolution state. Options: true\_positive\_mitigated, true\_posititve\_no\_action, false\_positive, unknown'. | string |     |
| **detection_uuid** | required | Detection UUID to resolve. | string |     |
| **resolution_comment** | optional | Optional comment for the resolution. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Detection resolved successfully. |
| action_result.data | string |     |     |

action: 'fortindr get detection rules'
--------------------------------------

Get a list of detection rules.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **limit** | optional | The number of records to return, default: 100, max: 1000. | numeric |     |
| **offset** | optional | The number of records to skip past. | numeric |     |
| **search** | optional | Filter name or category. | string |     |
| **enabled** | optional | Enabled rules only | boolean |     |
| **sort_by** | optional | The field to sort by: created, updated, detections, severity, confidence, category, last\_seen, detections\_muted. Defaults to updated. | string |     |
| **category** | optional | Category to filter by. | string |     |
| **severity** | optional | Filter by severity: high, moderate, low. | string |     |
| **confidence** | optional | Filter by confidence: high, moderate, low. | string |     |
| **sort_order** | optional | Sort direction ('asc' vs 'desc'). | string |     |
| **account_uuid** | optional | For those with access to multiple accounts, specify a single account to return results from. | string |     |
| **has_detections** | optional | Include rules that have unmuted, unresolved detections. | boolean |     |
| **rule\_account\_muted** | optional | Include muted rules: true / false. | boolean |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Detection Rules retrieved successfully. |
| action\_result.data.*.detection\_rule.enabled | boolean |     | true  <br>false |
| action\_result.data.*.detection\_rule.updated\_user\_uuid | string |     | 55f39b72-2622-4137-9051-bc2ff364f059 |
| action\_result.data.*.detection\_rule.rule_accounts | string |     |     |
| action\_result.data.*.detection\_rule.auto\_resolution\_minutes | numeric |     | 10080 |
| action\_result.data.*.detection\_rule.created | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.detection\_rule.account_uuid | string |     | 55f39b72-2622-4137-9051-bc2ff364f059 |
| action\_result.data.*.detection\_rule.confidence | string |     | high  <br>moderate  <br>low |
| action\_result.data.*.detection\_rule.name | string |     | AR T1595 |
| action\_result.data.*.detection\_rule.created\_user\_uuid | string |     | 55f39b72-2622-4137-9051-bc2ff364f059 |
| action\_result.data.*.detection\_rule.query_signature | string |     | ip IN ('1.1.1.1','2.2.2.2') AND event_type = 'dns' |
| action\_result.data.*.detection\_rule.shared\_account\_uuids | string |     | 55f39b72-2622-4137-9051-bc2ff364f059 |
| action\_result.data.*.detection\_rule.rule_accounts | string |     |     |
| action\_result.data.*.detection\_rule.run\_account\_uuids | string |     | \["55f39b72-2622-4137-9051-bc2ff364f059"\] |
| action\_result.data.*.detection\_rule.updated | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.detection\_rule.uuid | string |     | 55f39b72-2622-4137-9051-bc2ff364f059 |
| action\_result.data.*.detection\_rule.description | string |     |     |
| action\_result.data.*.detection\_rule.severity | string |     | high  <br>moderate  <br>low |
| action\_result.data.*.detection\_rule.category | string |     | Attack:Infection Vector |

action: 'fortindr get detections'
---------------------------------

Get information about the detections.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **limit** | optional | The number of records to return, default: 100, max: 10000. | numeric |     |
| **muted** | optional | List detections that a user muted: true / false. | boolean |     |
| **offset** | optional | The number of records to skip past. | numeric |     |
| **status** | optional | Filter by detection status: active, resolved. | string |     |
| **include** | optional | Include additional information in the response (i.e. 'rules,indicators' add the rules and the indicators to the response). (allows comma-separated lists) | string |     |
| **sort_by** | optional | Field to sort by (first\_seen, last\_seen, status, device\_ip, indicator\_count). | string |     |
| **device_ip** | optional | Device IP to filter by. | string |     |
| **rule_uuid** | optional | Filter to a specific rule. | string |     |
| **sensor_id** | optional | Sensor ID to filter by. | string |     |
| **muted_rule** | optional | List detections for muted rules. | boolean |     |
| **sort_order** | optional | Sort direction ('asc' vs 'desc'). | string |     |
| **account_uuid** | optional | For those with access to multiple accounts, specify a single account to return results from. | string |     |
| **muted_device** | optional | List detections for muted devices: true / false. | boolean |     |
| **active\_end\_date** | optional | Active end date to filter by (exclusive). | string |     |
| **created\_end\_date** | optional | Created end date to filter by (exclusive). | string |     |
| **active\_start\_date** | optional | Active start date to filter by (inclusive). | string |     |
| **created\_start\_date** | optional | Created start date to filter by (inclusive). | string |     |
| **created\_or\_shared\_end\_date** | optional | Created or shared end date to filter by (exclusive). | string |     |
| **created\_or\_shared\_start\_date** | optional | Created or shared start date to filter by (inclusive). | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Detections retrieved successfully. |
| action\_result.data.*.detections.*.muted\_rule | boolean |     | true  <br>false |
| action_result.data.*.detections.*.created | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.detections.*.account\_uuid | string |     | 1e5dbd92-9dca-4f36-bec5-c292172cbeaa |
| action\_result.data.*.detections.*.resolution\_timestamp | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.detections.*.first\_seen | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.detections.*.last\_seen | string |     | 2019-01-30T00:00:00.000Z |
| action_result.data.*.detections.*.muted | boolean |     | true  <br>false |
| action_result.data.*.detections.*.resolution | string |     | auto_resolved |
| action\_result.data.*.detections.*.muted\_user_uuid | string |     | d025f073-c01e-4ee9-a89b-72f972a75a16 |
| action\_result.data.*.detections.*.resolution\_user_uuid | string |     | b92cd6e0-dd24-4bee-838a-d0dfbeda621a |
| action_result.data.*.detections.*.status | string |     | active  <br>resolved |
| action\_result.data.*.detections.*.resolution\_comment | string |     |     |
| action\_result.data.*.detections.*.muted\_comment | string |     |     |
| action\_result.data.*.detections.*.sensor\_id | string |     | sen1 |
| action\_result.data.*.detections.*.rule\_uuid | string |     | 58c2e22d-8b64-43ac-89a2-6c82ce66935e |
| action_result.data.*.detections.*.uuid | string |     | cf576032-2f42-4b3e-90be-3c51e5128b03 |
| action\_result.data.*.detections.*.muted\_device_uuid | string |     | 55f39b72-2622-4137-9051-bc2ff364f059 |
| action_result.data.*.detections.*.updated | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.detections.*.device\_ip | string |     | 10.70.43.58 |

action: 'fortindr get entity file'
----------------------------------

Get information about a file.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **hash** | required | File hash. Can be an MD5, SHA1, or SHA256 hash of the file. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Entity file retrieved successfully. |
| action\_result.data.*.entity\_file.entity | string |     | 75ce20257379b1d8bd88f7bfb01c6a6e3a32221212c623fbf10de61e8c379ff8 |
| action\_result.data.*.entity\_file.sha1 | string |     | 8965f4209f82bb13e15172bdf672912eebc2132d |
| action\_result.data.*.entity\_file.sha256 | string |     | 75ce20257379b1d8bd88f7bfb01c6a6e3a32221212c623fbf10de61e8c379ff8 |
| action\_result.data.*.entity\_file.md5 | string |     | 95fcad6ceaefd749aa23fc5476863bb4 |
| action\_result.data.*.entity\_file.customer_id | string |     | gig |
| action\_result.data.*.entity\_file.names | string |     | \["TIAgentSetup.exe"\] |
| action\_result.data.*.entity\_file.mime_type | string |     | \["application/x-dosexec"\] |
| action\_result.data.*.entity\_file.first_seen | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.entity\_file.last_seen | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.entity\_file.bytes | numeric |     | 0   |
| action\_result.data.*.entity\_file.pe | string |     |     |
| action\_result.data.*.entity\_file.prevalence\_count\_internal | numeric |     | 0   |

action: 'fortindr get entity dhcp'
----------------------------------

Get DHCP information about an IP address.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **entity** | required | IP to get DHCP data for. | string |     |
| **end_date** | optional | The latest date after which to exclude results. Day granularity, inclusive. | string |     |
| **start_date** | optional | The earliest date before which to exclude results. Day granularity, inclusive. | string |     |
| **account_uuid** | optional | Limit results to the specified account UUID(s). Defaults to all accounts for which the user has permission. (allows comma-separated lists) | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Entity dhcp retrieved successfully. |
| action\_result.data.*.entity\_dhcp.customer_id | string |     | gig |
| action\_result.data.*.entity\_dhcp.hostnames | string |     | Somebody-iPhone |
| action\_result.data.*.entity\_dhcp.ip | string |     | 8.8.8.8 |
| action\_result.data.*.entity\_dhcp.lease_start | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.entity\_dhcp.lease_end | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.entity\_dhcp.mac | string |     | e3:84:2f:8e:50:e4 |
| action\_result.data.*.entity\_dhcp.sensor_id | string |     | sen1 |
| action\_result.data.*.entity\_dhcp.start\_lease\_as_long | numeric |     | 1618939557975 |

action: 'fortindr get entity pdns'
----------------------------------

Get passive DNS information about an IP or domain.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **limit** | optional | Maximum number of records to be returned. Default 1000. | numeric |     |
| **entity** | required | IP or Domain to get passive DNS data for. | string |     |
| **source** | optional | Limit the results to the specified data source(s). Note that not all Sources populate all fields. Supported sources are: ICEBRG_DNS. Case insensitive. (allows comma-separated lists) | string |     |
| **end_date** | optional | The latest date after which to exclude results. Day granularity, inclusive. | string |     |
| **start_date** | optional | The earliest date before which to exclude results. Day granularity, inclusive. | string |     |
| **record_type** | optional | Limit results to the specified DNS query type(s). Supported types are: A, AAAA, CNAME, MX, NS. Case insensitive. (allows comma-separated lists) | string |     |
| **account_uuid** | optional | Limit results to the specified account UUID(s). Defaults to all accounts for which the user has permission. (allows comma-separated lists) | string |     |
| **resolve_external** | optional | When true, the service will query non-ICEBRG data sources. false by default. | boolean |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Entity pdns retrieved successfully. |
| action\_result.data.*.entity\_pdns.account_uuid | string |     | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |
| action\_result.data.*.entity\_pdns.first_seen | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.entity\_pdns.last_seen | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.entity\_pdns.record_type | string |     | a   |
| action\_result.data.*.entity\_pdns.resolved | string |     | 8.8.8.8 |
| action\_result.data.*.entity\_pdns.sensor_id | string |     | sen1 |
| action\_result.data.*.entity\_pdns.customer_id | string |     | cust |
| action\_result.data.*.entity\_pdns.source | string |     | icebrg_dns |

action: 'fortindr get entity summary'
-------------------------------------

Get summary information about an IP or domain.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **entity** | required | Entity name to retrieve summary information for. | string |     |
| **entity_type** | optional | Type of the entity we are searching. Allowed values are: ip, domain or file. | string |     |
| **account_uuid** | optional | Account uuid to filter by. If absent, all the caller's allowed accounts will be queried. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Entity summary retrieved successfully. |
| action\_result.data.*.entity\_summary.entity | string |     | 8.8.8.8 |
| action\_result.data.*.entity\_summary.first_seen | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.entity\_summary.last_seen | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.entity\_summary.prevalence\_count\_internal | numeric |     | 8   |
| action\_result.data.*.entity\_summary.tags.*.text | string |     | external |
| action\_result.data.*.entity\_summary.tags.*.account_code | string |     | act |
| action\_result.data.*.entity\_summary.tags.*.user_uuid | string |     | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |
| action\_result.data.*.entity\_summary.tags.*.create_date | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.entity\_summary.tags.*.entity | string |     | 8.8.8.8 |
| action\_result.data.*.entity\_summary.tags.*.public | boolean |     |     |

action: 'fortindr get telemetry network'
----------------------------------------

Get network telemetry data grouped by time.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **limit** | optional | The maximum number of records to return, default: 100, max: 1000. | numeric |     |
| **offset** | optional | The number of records to skip past. Default: 0. | numeric |     |
| **end_date** | optional | End date to filter by. | string |     |
| **interval** | optional | The interval to filter by (day, month\_to\_day). | string |     |
| **sort_order** | optional | Sorts by account code first, then timestamp. asc or desc. The default is desc. | string |     |
| **start_date** | optional | Start date to filter by. | string |     |
| **account_code** | optional | Account code to filter by. | string |     |
| **latest\_each\_month** | optional | Filters out all but the latest day and month\_to\_date for each month. | boolean |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Telemetry network retrieved successfully. |
| action\_result.data.*.telemetry\_network\_usage.*.account\_code | string |     | gig |
| action\_result.data.*.telemetry\_network\_usage.*.percentile\_bps | numeric |     | 6050493542 |
| action\_result.data.*.telemetry\_network_usage.*.percentile | numeric |     | 95  |
| action\_result.data.*.telemetry\_network_usage.*.interval | string |     | day |
| action\_result.data.*.telemetry\_network_usage.*.timestamp | string |     | 2019-01-30T00:00:00.000Z |

action: 'fortindr get telemetry packetstats'
--------------------------------------------

Get packetstats telemetry data grouped by time.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **end_date** | optional | Scopes the returned metrics to dates before the given end_date. If empty returns most current packet stats. | string |     |
| **group_by** | optional | Option to group by the following fields: interface\_name, sensor\_id, account_code. | string |     |
| **interval** | optional | Aggregation interval. default by hour if not specified. | string |     |
| **sensor_id** | optional | Scopes the returned metrics to the interfaces of the specified sensor ID. | string |     |
| **start_date** | optional | Scopes the returned metrics to dates after the given start_date. If empty returns most current packet stats. | string |     |
| **account_code** | optional | Account code to filter by. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Telemetry packet stats retrieved successfully. |
| action\_result.data.*.telemetry\_packetstats.*.account_code | string |     | gig |
| action\_result.data.*.telemetry\_packetstats.*.timestamp | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.telemetry\_packetstats.*.interface_name | string |     |     |
| action\_result.data.*.telemetry\_packetstats.*.rx\_bits\_per_second | numeric |     | 168359035095 |
| action\_result.data.*.telemetry\_packetstats.*.rx_bytes | numeric |     | 1044065401242303200 |
| action\_result.data.*.telemetry\_packetstats.*.rx_errors | numeric |     | 543523121859 |
| action\_result.data.*.telemetry\_packetstats.*.rx_packets | numeric |     | 1511658249026538 |
| action\_result.data.*.telemetry\_packetstats.*.sensor_id | string |     | sen1 |
| action\_result.data.*.telemetry\_packetstats.*.tx_bytes | numeric |     | 1380372603073006 |
| action\_result.data.*.telemetry\_packetstats.*.tx_errors | numeric |     | 0   |
| action\_result.data.*.telemetry\_packetstats.*.tx_packets | numeric |     | 963173536282 |

action: 'fortindr get telemetry events'
---------------------------------------

Get event telemetry data grouped by time.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **end_date** | optional | End date/time to query for. The default is the current time. | string |     |
| **group_by** | optional | Optionally group results by: sensor\_id, event\_type. | string |     |
| **interval** | optional | Interval to group by: hour (default) or day. | string |     |
| **sensor_id** | optional | Sensor id to filter by. | string |     |
| **event_type** | optional | The type of event. | string |     |
| **start_date** | optional | Start date/time to query for. The default is 1 day ago for interval=hour or 30 days ago for interval=day. | string |     |
| **account_code** | optional | Account code to filter by. | string |     |
| **account_uuid** | optional | Account uuid to filter by. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Telemetry events retrieved successfully. |
| action\_result.data.*.telemetry\_events.*.timestamp | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.telemetry\_events.*.event_count | numeric |     | 1000 |
| action\_result.data.*.telemetry\_events.*.sensor_id | string |     | sen1 |
| action\_result.data.*.telemetry\_events.*.event_type | string |     | flow |
| action\_result.data.*.telemetry\_events.*.account_code | string |     | act |

action: 'fortindr create task'
------------------------------

Create a new PCAP task.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **bpf** | required | The Berkeley Packet Filter for capture filtering. | string |     |
| **name** | required | The name of the task. | string |     |
| **sensor_ids** | optional | List of sensor IDs, separated by ',', on which this task will run (separate multiple accounts by comma). (allows comma-separated lists) | string |     |
| **description** | required | A description for the task. | string |     |
| **account_uuid** | required | Account where the task will be created. | string |     |
| **requested\_end\_date** | required | The date the task will become inactive. (2019-12-31T23:59:59.000Z). | string |     |
| **requested\_start\_date** | required | The date the task will become active. (2019-01-30T00:00:00.000Z). | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Detection Rule created successfully. |
| action\_result.data.*.task.task\_uuid | string |     | 32329e78-c51f-4da4-bd56-6bfb35d84a9c |
| action_result.data.*.task.description | string |     |     |
| action_result.data.*.task.name | string |     | Meh-Ike phone 10001 |
| action\_result.data.*.task.sensor\_ids | string |     | \["sen1"\] |
| action\_result.data.*.task.account\_code | string |     | gig |
| action_result.data.*.task.bpf | string |     | src host x.x.x.x and dst port 10001 |
| action\_result.data.*.task.created\_uuid | string |     | 32329e78-c51f-4da4-bd56-6bfb35d84a9c |
| action\_result.data.*.task.updated\_uuid | string |     | 32329e78-c51f-4da4-bd56-6bfb35d84a9c |
| action\_result.data.*.task.created\_email | string |     | test@test.com |
| action\_result.data.*.task.updated\_email | string |     | test@test.com |
| action_result.data.*.task.created | string |     | 2019-01-30T00:00:00.000Z |
| action_result.data.*.task.updated | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.task.requested\_start_time | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.task.requested\_end_time | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.task.actual\_start_time | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.task.actual\_end_time | string |     | 2019-01-30T00:00:00.000Z |
| action_result.data.*.task.status | string |     | inactive |
| action_result.data.*.task.files | string |     |     |
| action\_result.data.*.task.has\_files | boolean |     | true  <br>false |

action: 'fortindr get tasks'
----------------------------

Get a list of all the PCAP tasks.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **task_uuid** | optional | Filter to a specific task. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Tasks retrieved successfully. |
| action\_result.data.*.tasks.*.task\_uuid | string |     | 32329e78-c51f-4da4-bd56-6bfb35d84a9c |
| action\_result.data.*.tasks.*.actual\_start_time | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.tasks.*.requested\_start_time | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.tasks.*.updated\_email | string |     | test@test.com |
| action\_result.data.*.tasks.*.created\_uuid | string |     | 32329e78-c51f-4da4-bd56-6bfb35d84a9c |
| action_result.data.*.tasks.*.created | string |     | 2019-01-30T00:00:00.000Z |
| action_result.data.*.tasks.*.name | string |     | Meh-Ike phone 10001 |
| action_result.data.*.tasks.*.status | string |     | inactive |
| action\_result.data.*.tasks.*.created\_email | string |     | test@test.com |
| action\_result.data.*.tasks.*.updated\_uuid | string |     | 32329e78-c51f-4da4-bd56-6bfb35d84a9c |
| action_result.data.*.tasks.*.bpf | string |     | src host x.x.x.x and dst port 10001 |
| action\_result.data.*.tasks.*.actual\_end_time | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.tasks.*.account\_code | string |     | gig |
| action\_result.data.*.tasks.*.requested\_end_time | string |     | 2019-01-30T00:00:00.000Z |
| action_result.data.*.tasks.*.updated | string |     | 2019-01-30T00:00:00.000Z |
| action_result.data.*.tasks.*.description | string |     |     |
| action\_result.data.*.tasks.*.has\_files | boolean |     | true  <br>false |
| action\_result.data.*.tasks.*.sensor\_ids | string |     | \["sen1"\] |
| action_result.data.*.tasks.*.files | string |     |     |

action: 'fortindr get devices'
------------------------------

Get a list of all devices.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **cidr** | optional | Filter devices that are under a specific CIDR. | string |     |
| **end_date** | optional | Filter devices based on when they were seen. | string |     |
| **sensor_id** | optional | Filter devices that were observed by a specific sensor. | string |     |
| **start_date** | optional | Filter devices based on when they were seen. | string |     |
| **traffic_direction** | optional | Filter devices that have been noted to only have a certain directionality of traffic ("external" vs "internal"). | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Devices retrieved successfully. |
| action_result.data.*.devices.*.date | string |     | 2019-01-30T00:00:00.000Z |
| action_result.data.*.devices.*.external | boolean |     | true  <br>false |
| action_result.data.*.devices.*.internal | boolean |     | true  <br>false |
| action\_result.data.*.devices.*.ip\_address | string |     | 8.8.8.8 |

action: 'fortindr get sensors'
------------------------------

Get a list of all sensors.

Type: **investigate**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **enabled** | optional | Filter by true or false. If not provided, all the sensors are returned. | boolean |     |
| **include** | optional | Include additional metadata such as status, interfaces, admin.sensor, admin.zeek, admin.suricata, and network_usage. (allows comma-separated lists) | string |     |
| **sensor_id** | optional | ID of the sensor to filter by. | string |     |
| **account_code** | optional | Account code to filter by. | string |     |
| **account_uuid** | optional | UUID of account to filter by. | string |     |

### Action Output

| DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES |
| --- | --- | --- | --- |
| action_result.status | string |     | success  <br>failed |
| action_result.summary | string |     |     |
| action_result.message | string |     | Sensors retrieved successfully. |
| action_result.data.*.sensors.*.created | string |     | 2019-01-30T00:00:00.000Z |
| action_result.data.*.sensors.*.updated | string |     | 2019-01-30T00:00:00.000Z |
| action\_result.data.*.sensors.*.sensor\_id | string |     | sen1 |
| action\_result.data.*.sensors.*.account\_code | string |     | gig |
| action_result.data.*.sensors.*.location | string |     | { "latitude": 0, "longitude": 0 } |
| action_result.data.*.sensors.*.subdivison | string |     | USA |
| action_result.data.*.sensors.*.city | string |     | San Jose |
| action_result.data.*.sensors.*.country | string |     | USA |
| action_result.data.*.sensors.*.tags | string |     | Demo Sensor |
| action\_result.data.*.sensors.*.pcap\_enabled | boolean |     | true  <br>false |

action: 'on poll'
-----------------

Retrieve latest Detections from the FortiNDR Cloud Service.

Type: **ingest**

Read only: **True**

### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS |
| --- | --- | --- | --- | --- |
| **end_time** | optional | Parameter Ignored in this app | numeric |     |
| **start_time** | optional | First Poll (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). | string |     |
| **container_id** | optional | Parameter Ignored in this app | numeric |     |
| **artifact_count** | optional | Parameter Ignored in this app | numeric |     |
| **container_count** | optional | Parameter Ignored in this app | numeric |     |

### Action Output

No Output

action: 'test connectivity'
---------------------------

Validate the asset configuration for connectivity using supplied configuration

Type: **test**

Read only: **True**

### Action Parameters

No parameters are required for this action

### Action Output

No Output
