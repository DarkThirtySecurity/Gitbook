# SIGMA Templates

## AWS Template

```text
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

```text
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

```text
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

```text
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

```text
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

```text
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

```text
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



























