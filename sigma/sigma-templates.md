# SIGMA Templates

## General

```
title: a short capitalized title with less than 50 characters
id: generate one here https://www.uuidgenerator.net/version4
status: experimental
description: A description of what your rule is meant to detect 
references:
    - A list of all references that can help a reader or analyst understand the meaning of a triggered rule
tags:
    - attack.execution  # example MITRE ATT&CK category
    - attack.t1059      # example MITRE ATT&CK technique id
    - car.2014-04-003   # example CAR id
author: Michael Haag, Florian Roth, Markus Neis  # example, a list of authors
date: 2018/04/06  # Rule date
logsource:                      # important for the field mapping in predefined or your additional config files
    category: process_creation  # In this example we choose the category 'process_creation'
    product: windows            # the respective product
detection:
    selection:
        FieldName: 'StringValue'
        FieldName: IntegerValue
        FieldName|modifier: 'Value'
    condition: selection
fields:
    - fields in the log source that are important to investigate further
falsepositives:
    - describe possible false positive conditions to help the analysts in their investigation
level: one of four levels (low, medium, high, critical)
```

## AWS Template

```
title: AWS 
id:  
description: Detects when a
author: Austin Songer @austinsonger
status: experimental
date: 2021/
references:
    - 
logsource:
    service: cloudtrail
detection:
    selection:
        eventSource: <##>.amazonaws.com
        eventName: 
    condition: selection
level: low
tags:
    - attack.
    - attack.
    - attack.
falsepositives:
 - <Placeholder> being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - <Placeholder> modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
```

## Azure

```
title: Azure 
id: 
description: Detects when a 
author: Austin Songer @austinsonger
status: experimental
date: 2021/
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
    - 
    - 
logsource:
  service: azure.activitylogs
detection:
    selection:
        properties.message: 
            - 
            - 
            - 
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - <Placeholder> being modified or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - <Placeholder> modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```



## Google Cloud Platform Template

```
title: GCP  
id: 
description: Detects when a
author: Austin Songer
status: experimental
date: 2021/
references:
    - 
logsource:
  service: gcp.audit
detection:
    selection:
        gcp.audit.method_name: 
            - 
            - 
    condition: selection
level: medium
tags:
    - attack.
falsepositives:
 - <Placeholder> being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - <Placeholder> modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
```



## Google Workspace Template

```
title: Google Workspace 
id: 
description: Detects when a 
author: Austin Songer @austinsonger
status: experimental
date: 2021/
references:
    - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
    - https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-user-settings
logsource:
  service: google_workspace.admin
detection:
    selection:
        eventService: admin.googleapis.com
        eventName: 
            - 
            - 
    condition: selection
level: medium
tags:
    - attack.
    - atack.t
falsepositives:
 - Unknown

```



## Microsoft 365 Template

```
title: Microsoft 365 - 
id: 
status: experimental
description: Detects when a  
author: Austin Songer @austinsonger
date: 2021/
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
logsource:
    category: 
    service: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: ""
        status: success
    condition: selection
level: medium
tags:
    - attack.initial_access
    - 
falsepositives:
    - 
```



## Okta Template

```
title: Okta 
id: 
description: Detects when a
author: Austin Songer @austinsonger
status: experimental
date: 2021/
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
logsource:
  service: okta
detection:
    selection:
        eventtype: 
            - 
            - 
        displaymessage:
            - 
            -
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Okta <Placeholder> being modified or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Okta <Placeholder> modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
```



## Windows Templates

### Registry Event Template

```
title: 
id: 
description: Detects when 
status: experimental
date: 2021/
author: Austin Songer @austinsonger
references:
    - 
logsource:
    category: registry_event
    product: windows	
detection:
    selection:
        EventType: SetValue
        TargetObject|contains: ''
        TargetObject|endswith:
            - 
        Details: 'DWORD ()'
    condition: selection	
level: high
tags:
    - attack.defense_evasion
falsepositives:
    - Unknown
```

























